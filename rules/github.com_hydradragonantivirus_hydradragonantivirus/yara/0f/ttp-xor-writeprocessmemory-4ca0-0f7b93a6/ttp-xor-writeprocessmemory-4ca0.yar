rule TTP_XOR_WriteProcessMemory_4ca0 {
  strings:
    $key_4ca0 = { 1b d2 [2] 29 f0 [2] 2f c5 [2] 01 c5 [2] 3e d9 }

  condition:
    any of them
}