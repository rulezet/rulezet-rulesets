rule PEiD_00860_Go32Stub_v_2_00_DOS_Extender_ {
  meta:
    description = "[Go32Stub v.2.00 DOS-Extender]"
    ep_only     = "true"

  strings:
    $a = { 0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 80 }

  condition:
    $a
}