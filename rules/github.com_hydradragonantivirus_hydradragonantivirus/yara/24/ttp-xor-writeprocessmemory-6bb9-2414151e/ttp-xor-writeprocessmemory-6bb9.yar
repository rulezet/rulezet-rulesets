rule TTP_XOR_WriteProcessMemory_6bb9 {
  strings:
    $key_6bb9 = { 3c cb [2] 0e e9 [2] 08 dc [2] 26 dc [2] 19 c0 }

  condition:
    any of them
}