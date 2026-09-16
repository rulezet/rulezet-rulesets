rule TTP_XOR_WriteProcessMemory_56c0 {
  strings:
    $key_56c0 = { 01 b2 [2] 33 90 [2] 35 a5 [2] 1b a5 [2] 24 b9 }

  condition:
    any of them
}