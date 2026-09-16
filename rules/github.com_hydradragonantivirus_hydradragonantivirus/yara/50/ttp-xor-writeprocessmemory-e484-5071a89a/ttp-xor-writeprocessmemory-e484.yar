rule TTP_XOR_WriteProcessMemory_e484 {
  strings:
    $key_e484 = { b3 f6 [2] 81 d4 [2] 87 e1 [2] a9 e1 [2] 96 fd }

  condition:
    any of them
}