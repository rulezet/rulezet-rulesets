rule TTP_XOR_WriteProcessMemory_1db9 {
  strings:
    $key_1db9 = { 4a cb [2] 78 e9 [2] 7e dc [2] 50 dc [2] 6f c0 }

  condition:
    any of them
}