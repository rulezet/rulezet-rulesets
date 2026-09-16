import "pe"
rule ExeSplitter_1_3__Split_Crypt_Method_____Bill_Prisoner___TPOC {
  strings:
    $a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 ?? ?? ?? ?? 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 ?? ?? ?? ?? ?? ?? ?? 66 }

  condition:
    $a0 at pe.entry_point
}