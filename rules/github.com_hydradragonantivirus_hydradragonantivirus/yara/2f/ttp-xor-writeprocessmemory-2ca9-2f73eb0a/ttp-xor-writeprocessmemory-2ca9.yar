rule TTP_XOR_WriteProcessMemory_2ca9 {
  strings:
    $key_2ca9 = { 7b db [2] 49 f9 [2] 4f cc [2] 61 cc [2] 5e d0 }

  condition:
    any of them
}