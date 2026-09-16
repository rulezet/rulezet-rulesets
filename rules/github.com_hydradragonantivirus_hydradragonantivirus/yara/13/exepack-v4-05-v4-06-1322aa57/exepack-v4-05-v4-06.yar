import "pe"
rule EXEPACK_v4_05__v4_06 {
  strings:
    $a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 06 ?? ?? 8E C0 8B 0E ?? ?? 8B F9 4F 8B F7 FD F3 A4 }

  condition:
    $a0 at pe.entry_point
}