import "pe"
rule Simple_UPX_Cryptor_v30_4_2005_rule__One_layer_encryption______MANtiCORE {
  strings:
    $a0 = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }

  condition:
    $a0 at pe.entry_point
}