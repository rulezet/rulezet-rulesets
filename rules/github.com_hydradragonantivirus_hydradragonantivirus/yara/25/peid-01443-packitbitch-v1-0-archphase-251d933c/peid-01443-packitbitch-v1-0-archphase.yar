rule PEiD_01443_PackItBitch_V1_0___archphase_ {
  meta:
    description = "[PackItBitch V1.0-> archphase]"
    ep_only     = "true"

  strings:
    $a = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }

  condition:
    $a
}