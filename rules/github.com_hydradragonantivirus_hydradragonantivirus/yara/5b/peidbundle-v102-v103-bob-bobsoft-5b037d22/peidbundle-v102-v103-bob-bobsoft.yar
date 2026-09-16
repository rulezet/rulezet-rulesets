import "pe"
rule _PEiDBundle_v102__v103__BoB__BobSoft_ {
  meta:
    description = "PEiD-Bundle v1.02 - v1.03 --> BoB / BobSoft"

  strings:
    $0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

  condition:
    $0 at pe.entry_point
}