rule PEiD_00845_Fuck_n_Joy_1_0c____UsAr_ {
  meta:
    description = "[Fuck'n'Joy 1.0c -> UsAr]"
    ep_only     = "false"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 }

  condition:
    $a
}