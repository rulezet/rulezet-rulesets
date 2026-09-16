rule PEiD_02431_UPX_v0_60___v0_61_ {
  meta:
    description = "[UPX v0.60 - v0.61]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 }

  condition:
    $a
}