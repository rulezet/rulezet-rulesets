rule TTP_XOR_WriteProcessMemory_e4b1 {
  strings:
    $key_e4b1 = { b3 c3 [2] 81 e1 [2] 87 d4 [2] a9 d4 [2] 96 c8 }

  condition:
    any of them
}