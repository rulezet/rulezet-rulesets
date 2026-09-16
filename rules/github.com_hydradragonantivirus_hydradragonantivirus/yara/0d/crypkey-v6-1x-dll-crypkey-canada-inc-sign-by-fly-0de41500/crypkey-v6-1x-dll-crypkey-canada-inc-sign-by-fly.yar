import "pe"
rule CrypKey_V6_1X_DLL____CrypKey__Canada__Inc______Sign_By_fly {
  strings:
    $a0 = { 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8 }

  condition:
    $a0 at pe.entry_point
}