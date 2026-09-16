rule PEiD_00040_AdFlt2_ {
  meta:
    description = "[AdFlt2]"
    ep_only     = "true"

  strings:
    $a = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD }

  condition:
    $a
}