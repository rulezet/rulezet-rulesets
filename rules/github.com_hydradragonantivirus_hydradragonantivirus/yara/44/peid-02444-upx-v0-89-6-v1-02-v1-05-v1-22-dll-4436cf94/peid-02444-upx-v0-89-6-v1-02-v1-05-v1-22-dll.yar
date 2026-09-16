rule PEiD_02444_UPX_v0_89_6___v1_02___v1_05___v1_22_DLL_ {
  meta:
    description = "[UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL]"
    ep_only     = "true"

  strings:
    $a = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

  condition:
    $a
}