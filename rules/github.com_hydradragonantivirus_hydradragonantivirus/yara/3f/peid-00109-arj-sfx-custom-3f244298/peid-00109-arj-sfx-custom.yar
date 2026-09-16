rule PEiD_00109_ARJ_SFX_Custom_ {
  meta:
    description = "[ARJ SFX Custom]"
    ep_only     = "true"

  strings:
    $a = { 60 BE 15 F0 40 00 8D BE EB 1F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }

  condition:
    $a
}