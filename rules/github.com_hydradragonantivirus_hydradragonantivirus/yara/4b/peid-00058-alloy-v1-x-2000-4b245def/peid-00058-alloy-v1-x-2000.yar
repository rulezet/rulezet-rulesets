rule PEiD_00058_Alloy_v1_x_2000_ {
  meta:
    description = "[Alloy v1.x.2000]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }

  condition:
    $a
}