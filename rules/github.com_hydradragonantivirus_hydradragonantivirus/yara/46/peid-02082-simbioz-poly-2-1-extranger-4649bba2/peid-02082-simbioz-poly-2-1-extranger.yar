rule PEiD_02082_SimbiOZ_Poly_2_1____Extranger_ {
  meta:
    description = "[SimbiOZ Poly 2.1 -> Extranger]"
    ep_only     = "true"

  strings:
    $a = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90 }

  condition:
    $a
}