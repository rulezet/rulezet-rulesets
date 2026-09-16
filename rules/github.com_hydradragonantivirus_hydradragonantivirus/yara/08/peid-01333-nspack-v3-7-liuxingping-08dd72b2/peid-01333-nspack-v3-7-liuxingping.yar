rule PEiD_01333_NsPacK_V3_7____LiuXingPing_ {
  meta:
    description = "[NsPacK V3.7 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }

  condition:
    $a
}