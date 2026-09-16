rule PEiD_02075_Shrinker_v3_3_ {
  meta:
    description = "[Shrinker v3.3]"
    ep_only     = "true"

  strings:
    $a = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

  condition:
    $a
}