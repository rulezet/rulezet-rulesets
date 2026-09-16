rule TTP_XOR_WriteProcessMemory_28b9 {
  strings:
    $key_28b9 = { 7f cb [2] 4d e9 [2] 4b dc [2] 65 dc [2] 5a c0 }

  condition:
    any of them
}