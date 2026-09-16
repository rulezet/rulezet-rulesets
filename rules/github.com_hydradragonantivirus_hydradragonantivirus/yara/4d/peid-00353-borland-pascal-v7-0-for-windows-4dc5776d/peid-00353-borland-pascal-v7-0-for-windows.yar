import "pe"
rule PEiD_00353_Borland_Pascal_v7_0_for_Windows_ {
  meta:
    description = "[Borland Pascal v7.0 for Windows]"
    ep_only     = "true"

  strings:
    $a = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }

  condition:
    $a at pe.entry_point
}