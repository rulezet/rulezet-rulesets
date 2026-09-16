rule TTP_XOR_WriteProcessMemory_1ca9 {
  strings:
    $key_1ca9 = { 4b db [2] 79 f9 [2] 7f cc [2] 51 cc [2] 6e d0 }

  condition:
    any of them
}