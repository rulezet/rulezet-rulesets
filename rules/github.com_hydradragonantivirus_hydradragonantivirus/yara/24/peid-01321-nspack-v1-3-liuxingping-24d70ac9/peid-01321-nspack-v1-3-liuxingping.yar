rule PEiD_01321_nSpack_V1_3____LiuXingPing_ {
  meta:
    description = "[nSpack V1.3 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }

  condition:
    $a
}