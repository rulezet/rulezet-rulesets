rule TTP_XOR_WriteProcessMemory_4db9 {
  strings:
    $key_4db9 = { 1a cb [2] 28 e9 [2] 2e dc [2] 00 dc [2] 3f c0 }

  condition:
    any of them
}