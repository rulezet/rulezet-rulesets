import "pe"
rule APatch_GUI_v1_1 {
  strings:
    $a0 = { 52 31 C0 E8 FF FF FF FF }

  condition:
    $a0 at pe.entry_point
}