import "pe"
rule SLVc0deProtector_1_1x____SLV___ICU {
  strings:
    $a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}