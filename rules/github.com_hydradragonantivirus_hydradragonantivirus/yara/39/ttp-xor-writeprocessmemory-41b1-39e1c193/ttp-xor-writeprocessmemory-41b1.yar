rule TTP_XOR_WriteProcessMemory_41b1 {
  strings:
    $key_41b1 = { 16 c3 [2] 24 e1 [2] 22 d4 [2] 0c d4 [2] 33 c8 }

  condition:
    any of them
}