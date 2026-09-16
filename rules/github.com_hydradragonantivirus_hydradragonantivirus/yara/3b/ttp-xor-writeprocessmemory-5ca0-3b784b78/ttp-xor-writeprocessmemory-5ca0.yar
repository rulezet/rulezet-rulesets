rule TTP_XOR_WriteProcessMemory_5ca0 {
  strings:
    $key_5ca0 = { 0b d2 [2] 39 f0 [2] 3f c5 [2] 11 c5 [2] 2e d9 }

  condition:
    any of them
}