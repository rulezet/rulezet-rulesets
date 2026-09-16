rule TTP_XOR_WriteProcessMemory_3ca9 {
  strings:
    $key_3ca9 = { 6b db [2] 59 f9 [2] 5f cc [2] 71 cc [2] 4e d0 }

  condition:
    any of them
}