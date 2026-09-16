rule PEiD_01476_PC_Guard_v4_05d__v4_10d__v4_15d_ {
  meta:
    description = "[PC-Guard v4.05d, v4.10d, v4.15d]"
    ep_only     = "true"

  strings:
    $a = { FC 55 50 E8 00 00 00 00 5D EB 01 }

  condition:
    $a
}