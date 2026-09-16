rule PEiD_00981_LCC_Win32_ {
  meta:
    description = "[LCC-Win32]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 10 30 40 00 68 9A 10 40 }

  condition:
    $a
}