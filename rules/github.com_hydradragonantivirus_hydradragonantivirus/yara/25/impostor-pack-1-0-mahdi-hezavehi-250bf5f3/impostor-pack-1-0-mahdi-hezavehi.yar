import "pe"
rule IMPostor_Pack_1_0____Mahdi_Hezavehi {
  strings:
    $a0 = { BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00 }

  condition:
    $a0 at pe.entry_point
}