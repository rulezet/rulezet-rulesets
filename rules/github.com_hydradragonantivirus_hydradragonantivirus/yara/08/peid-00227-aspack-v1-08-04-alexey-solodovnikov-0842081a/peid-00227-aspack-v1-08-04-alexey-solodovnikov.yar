rule PEiD_00227_ASPack_v1_08_04____Alexey_Solodovnikov_ {
  meta:
    description = "[ASPack v1.08.04 -> Alexey Solodovnikov]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 41 06 00 00 EB 41 }

  condition:
    $a
}