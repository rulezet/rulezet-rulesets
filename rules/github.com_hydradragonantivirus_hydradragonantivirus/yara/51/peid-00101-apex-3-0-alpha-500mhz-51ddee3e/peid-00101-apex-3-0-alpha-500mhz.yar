rule PEiD_00101_Apex_3_0_alpha____500mhz_ {
  meta:
    description = "[Apex 3.0 alpha -> 500mhz]"
    ep_only     = "false"

  strings:
    $a = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3 }

  condition:
    $a
}