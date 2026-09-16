rule TTP_XOR_WriteProcessMemory_5db9 {
  strings:
    $key_5db9 = { 0a cb [2] 38 e9 [2] 3e dc [2] 10 dc [2] 2f c0 }

  condition:
    any of them
}