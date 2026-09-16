rule PEiD_00543_EPW_v1_2_ {
  meta:
    description = "[EPW v1.2]"
    ep_only     = "true"

  strings:
    $a = { 06 57 1E 56 55 52 51 53 50 2E ?? ?? ?? ?? 8C C0 05 ?? ?? 2E ?? ?? ?? 8E D8 A1 ?? ?? 2E }

  condition:
    $a
}