rule SUSP_ELF_SEA_TURTLE_SOCAT_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule to find suspected SOCAT variant used by Sea Turtle."
    reference   = "https://www.huntandhackett.com/blog/turkish-espionage-campaigns"
    DaysofYARA  = "16/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-29"
    version     = "1.0"
    hash        = "71c81cb46dd1903f12f3aef844b0fc559f31e2f613a8ae91ffb5630bc7011ef5"

  strings:
    $ = { 45 8a 11 41 ?? ?? ?? 74 ?? 4d 8d 61 01 4c 39 e6 74 ?? 45 0f b6 61 01 41 ?? ?? ?? 41 c1 e2 08 45 09 e2 85 c0 79 ?? 49 8d 41 02 29 d0 4d 63 ca 49 39 e9 7d ?? 49 01 f9 eb ?? 45 84 d2 74 ?? 49 39 cb 49 89 cc 74 ?? 4d 8d 63 01 41 ?? ?? ?? 45 0f b6 19 4d 8d 69 01 49 89 f2 4d 29 ea 4d 39 d3 7d ?? 4d 89 c2 4d 29 e2 4d 39 d3 7d ?? 45 31 d2 4d 39 da 74 ?? 47 8a 74 11 01 47 88 34 14 49 ff c2 eb ?? 85 c0 41 c6 03 ?? 79 ?? 49 8d 41 01 29 d0 eb ?? 4f 8d 1c 14 4f 8d 4c 15 ?? 48 83 c3 02 e9 ?? ?? ?? ?? 5b 5d }

  condition:
    uint32(0) == 0x464c457f
    and all of them
}