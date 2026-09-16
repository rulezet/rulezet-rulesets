rule TTP_XOR_WriteProcessMemory_68b9 {
  strings:
    $key_68b9 = { 3f cb [2] 0d e9 [2] 0b dc [2] 25 dc [2] 1a c0 }

  condition:
    any of them
}