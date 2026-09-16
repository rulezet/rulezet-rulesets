rule TTP_XOR_WriteProcessMemory_e4d6 {
  strings:
    $key_e4d6 = { b3 a4 [2] 81 86 [2] 87 b3 [2] a9 b3 [2] 96 af }

  condition:
    any of them
}