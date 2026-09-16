rule PEiD_02499_Virogen_Crypt_v0_75_ {
  meta:
    description = "[Virogen Crypt v0.75]"
    ep_only     = "true"

  strings:
    $a = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }

  condition:
    $a
}