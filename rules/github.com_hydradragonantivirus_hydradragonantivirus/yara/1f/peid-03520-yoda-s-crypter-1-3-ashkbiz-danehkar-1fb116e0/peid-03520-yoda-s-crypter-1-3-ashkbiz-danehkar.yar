rule PEiD_03520_yoda_s_Crypter_1_3____Ashkbiz_Danehkar_ {
  meta:
    description = "[yoda's Crypter 1.3 -> Ashkbiz Danehkar]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 }

  condition:
    $a
}