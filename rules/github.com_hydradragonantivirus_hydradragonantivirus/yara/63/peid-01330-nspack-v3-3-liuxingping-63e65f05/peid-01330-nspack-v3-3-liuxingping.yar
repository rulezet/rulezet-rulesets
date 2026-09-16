rule PEiD_01330_NsPacK_V3_3____LiuXingPing_ {
  meta:
    description = "[NsPacK V3.3 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74 }

  condition:
    $a
}