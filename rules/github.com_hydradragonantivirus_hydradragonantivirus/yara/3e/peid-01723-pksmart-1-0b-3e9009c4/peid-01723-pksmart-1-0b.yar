rule PEiD_01723_Pksmart_1_0b_ {
  meta:
    description = "[Pksmart 1.0b]"
    ep_only     = "true"

  strings:
    $a = { BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3 }

  condition:
    $a
}