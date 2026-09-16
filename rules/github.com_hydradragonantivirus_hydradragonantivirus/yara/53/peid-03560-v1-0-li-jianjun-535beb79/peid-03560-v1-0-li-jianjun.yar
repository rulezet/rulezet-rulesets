rule PEiD_03560____v1_0____Li_Jianjun_ {
  meta:
    description = "[convert base64 to ascii w4nDvg== v1.0 -> Li-Jianjun]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 }

  condition:
    $a
}