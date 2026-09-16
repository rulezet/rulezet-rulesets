rule TTP_XOR_WriteProcessMemory_d4d6 {
  strings:
    $key_d4d6 = { 83 a4 [2] b1 86 [2] b7 b3 [2] 99 b3 [2] a6 af }

  condition:
    any of them
}