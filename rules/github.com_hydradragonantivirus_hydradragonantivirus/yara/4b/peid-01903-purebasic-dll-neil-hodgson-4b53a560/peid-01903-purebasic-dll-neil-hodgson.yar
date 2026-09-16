rule PEiD_01903_PureBasic_DLL____Neil_Hodgson_ {
  meta:
    description = "[PureBasic DLL -> Neil Hodgson]"
    ep_only     = "true"

  strings:
    $a = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

  condition:
    $a
}