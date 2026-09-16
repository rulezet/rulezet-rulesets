rule TTP_XOR_WriteProcessMemory_58b9 {
  strings:
    $key_58b9 = { 0f cb [2] 3d e9 [2] 3b dc [2] 15 dc [2] 2a c0 }

  condition:
    any of them
}