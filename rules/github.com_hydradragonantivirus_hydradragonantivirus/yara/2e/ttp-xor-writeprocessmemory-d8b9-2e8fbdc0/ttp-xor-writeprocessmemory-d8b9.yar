rule TTP_XOR_WriteProcessMemory_d8b9 {
  strings:
    $key_d8b9 = { 8f cb [2] bd e9 [2] bb dc [2] 95 dc [2] aa c0 }

  condition:
    any of them
}