rule PEiD_01749_PolyEnE_V0_01_____Lennart_Hedlund_ {
  meta:
    description = "[PolyEnE V0.01+ -> Lennart Hedlund]"
    ep_only     = "false"

  strings:
    $a = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }

  condition:
    $a
}