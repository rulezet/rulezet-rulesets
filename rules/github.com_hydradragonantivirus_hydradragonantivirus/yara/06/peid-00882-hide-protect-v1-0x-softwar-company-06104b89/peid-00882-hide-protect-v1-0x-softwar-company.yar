rule PEiD_00882_Hide_Protect_V1_0X___SoftWar_Company_ {
  meta:
    description = "[Hide&Protect V1.0X-> SoftWar Company]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 E9 D8 }

  condition:
    $a
}