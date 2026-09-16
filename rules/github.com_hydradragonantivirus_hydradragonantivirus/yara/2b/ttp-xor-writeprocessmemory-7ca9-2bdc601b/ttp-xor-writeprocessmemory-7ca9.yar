rule TTP_XOR_WriteProcessMemory_7ca9 {
  strings:
    $key_7ca9 = { 2b db [2] 19 f9 [2] 1f cc [2] 31 cc [2] 0e d0 }

  condition:
    any of them
}