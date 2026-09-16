rule PEiD_00232_ASPack_v2_000____Alexey_Solodovnikov_ {
  meta:
    description = "[ASPack v2.000 -> Alexey Solodovnikov]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 70 05 00 00 EB 4C }

  condition:
    $a
}