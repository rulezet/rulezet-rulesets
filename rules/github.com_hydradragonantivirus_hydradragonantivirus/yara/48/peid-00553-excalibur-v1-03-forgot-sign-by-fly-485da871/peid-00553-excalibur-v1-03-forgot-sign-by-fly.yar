rule PEiD_00553_Excalibur_V1_03____forgot___Sign_by_fly_ {
  meta:
    description = "[Excalibur V1.03 -> forgot ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }

  condition:
    $a
}