rule PEiD_01328_NsPacK_V3_1____LiuXingPing_ {
  meta:
    description = "[NsPacK V3.1 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }

  condition:
    $a
}