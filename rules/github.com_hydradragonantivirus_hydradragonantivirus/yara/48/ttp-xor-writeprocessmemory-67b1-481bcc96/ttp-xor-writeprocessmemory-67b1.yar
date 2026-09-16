rule TTP_XOR_WriteProcessMemory_67b1 {
  strings:
    $key_67b1 = { 30 c3 [2] 02 e1 [2] 04 d4 [2] 2a d4 [2] 15 c8 }

  condition:
    any of them
}