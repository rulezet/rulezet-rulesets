rule PEiD_00091_AntiDote_v1_4_osCE__Sing_by_osC__CoDeR_ {
  meta:
    description = "[AntiDote v1.4 osCE *Sing by osC++CoDeR]"
    ep_only     = "true"

  strings:
    $a = { 68 95 01 00 00 E8 D0 FD FF FF 68 95 01 00 00 E8 C3 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 }

  condition:
    $a
}