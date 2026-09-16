rule TTP_XOR_WriteProcessMemory_6ca0 {
  strings:
    $key_6ca0 = { 3b d2 [2] 09 f0 [2] 0f c5 [2] 21 c5 [2] 1e d9 }

  condition:
    any of them
}