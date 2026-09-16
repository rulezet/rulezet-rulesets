rule PEiD_00045_AHPack_0_1____FEUERRADER_ {
  meta:
    description = "[AHPack 0.1 -> FEUERRADER]"
    ep_only     = "true"

  strings:
    $a = { 60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00 }

  condition:
    $a
}