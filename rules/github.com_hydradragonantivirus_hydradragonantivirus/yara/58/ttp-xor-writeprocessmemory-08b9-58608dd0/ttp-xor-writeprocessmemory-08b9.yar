rule TTP_XOR_WriteProcessMemory_08b9 {
  strings:
    $key_08b9 = { 5f cb [2] 6d e9 [2] 6b dc [2] 45 dc [2] 7a c0 }

  condition:
    any of them
}