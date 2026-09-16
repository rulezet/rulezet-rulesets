rule TTP_XOR_WriteProcessMemory_e9b9 {
  strings:
    $key_e9b9 = { be cb [2] 8c e9 [2] 8a dc [2] a4 dc [2] 9b c0 }

  condition:
    any of them
}