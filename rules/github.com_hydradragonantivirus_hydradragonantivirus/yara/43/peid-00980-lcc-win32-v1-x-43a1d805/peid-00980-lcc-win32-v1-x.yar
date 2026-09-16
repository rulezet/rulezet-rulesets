rule PEiD_00980_LCC_Win32_v1_x_ {
  meta:
    description = "[LCC Win32 v1.x]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }

  condition:
    $a
}