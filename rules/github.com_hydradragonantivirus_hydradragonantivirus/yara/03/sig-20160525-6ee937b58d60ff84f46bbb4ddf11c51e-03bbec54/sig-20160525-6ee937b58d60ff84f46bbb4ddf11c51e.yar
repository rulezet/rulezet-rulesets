rule sig_20160525_6ee937b58d60ff84f46bbb4ddf11c51e {
  meta:
    description = "datamaliciousorder - file 20160525_6ee937b58d60ff84f46bbb4ddf11c51e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4f50e3ef777ec251ca923763459ba71e9e794d995aa1a9fb71e2685f789fbaa"

  strings:
    $s1 = "\\n;)4 ,4-]))(};cthb nruter{)(deerdc noitcnuf( + tsilslianbmuhtob + ssorcab[eixodb(]))(};sdneto nruter{)(ssorcao noitcnuf( + dee" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}