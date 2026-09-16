rule PEiD_00964_Krypton_v0_4_ {
  meta:
    description = "[Krypton v0.4]"
    ep_only     = "true"

  strings:
    $a = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }

  condition:
    $a
}