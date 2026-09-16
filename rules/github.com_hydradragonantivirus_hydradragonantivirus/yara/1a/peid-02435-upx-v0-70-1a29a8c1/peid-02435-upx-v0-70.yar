rule PEiD_02435_UPX_v0_70_ {
  meta:
    description = "[UPX v0.70]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }

  condition:
    $a
}