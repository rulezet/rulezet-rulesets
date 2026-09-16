rule PEiD_00881_Hide_Protect_1_016____SoftWar_Company_ {
  meta:
    description = "[Hide&Protect 1.016 -> SoftWar Company]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 E9 D8 ?? 05 00 95 ?? 53 00 95 4A 50 00 }

  condition:
    $a
}