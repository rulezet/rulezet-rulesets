import "pe"
rule FSG_v1_31 {
  strings:
    $a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }

  condition:
    $a0 at pe.entry_point
}