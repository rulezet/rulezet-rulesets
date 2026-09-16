rule TTP_XOR_WriteProcessMemory_1ca0 {
  strings:
    $key_1ca0 = { 4b d2 [2] 79 f0 [2] 7f c5 [2] 51 c5 [2] 6e d9 }

  condition:
    any of them
}