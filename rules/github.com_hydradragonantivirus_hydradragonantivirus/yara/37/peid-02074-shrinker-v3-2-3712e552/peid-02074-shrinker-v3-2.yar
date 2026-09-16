rule PEiD_02074_Shrinker_v3_2_ {
  meta:
    description = "[Shrinker v3.2]"
    ep_only     = "true"

  strings:
    $a = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }

  condition:
    $a
}