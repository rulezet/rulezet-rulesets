rule PEiD_02237_Themida_WinLicense_V1_0_0_0_V1_8_0_0____Oreans_Technologies___Sign_by_fly_ {
  meta:
    description = "[Themida/WinLicense V1.0.0.0-V1.8.0.0 -> Oreans Technologies ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }

  condition:
    $a
}