rule TTP_XOR_WriteProcessMemory_0db9 {
  strings:
    $key_0db9 = { 5a cb [2] 68 e9 [2] 6e dc [2] 40 dc [2] 7f c0 }

  condition:
    any of them
}