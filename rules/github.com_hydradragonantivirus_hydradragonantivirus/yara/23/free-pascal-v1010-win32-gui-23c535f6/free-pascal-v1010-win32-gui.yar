import "pe"
rule _Free_Pascal_v1010_win32_GUI_ {
  meta:
    description = "Free Pascal v1.0.10 (win32 GUI)"

  strings:
    $0 = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 }

  condition:
    $0 at pe.entry_point
}