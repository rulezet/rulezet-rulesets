rule TTP_XOR_WriteProcessMemory_7db9 {
  strings:
    $key_7db9 = { 2a cb [2] 18 e9 [2] 1e dc [2] 30 dc [2] 0f c0 }

  condition:
    any of them
}