rule PEiD_00062_ANDpakk2_0_06___by_Dmitry__AND__Andreev_ {
  meta:
    description = "[ANDpakk2 0.06 - by Dmitry \"AND\" Andreev]"
    ep_only     = "true"

  strings:
    $a = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 }

  condition:
    $a
}