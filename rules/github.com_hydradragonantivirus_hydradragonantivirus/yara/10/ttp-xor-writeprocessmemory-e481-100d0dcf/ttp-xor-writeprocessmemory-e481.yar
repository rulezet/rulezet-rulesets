rule TTP_XOR_WriteProcessMemory_e481 {
  strings:
    $key_e481 = { b3 f3 [2] 81 d1 [2] 87 e4 [2] a9 e4 [2] 96 f8 }

  condition:
    any of them
}