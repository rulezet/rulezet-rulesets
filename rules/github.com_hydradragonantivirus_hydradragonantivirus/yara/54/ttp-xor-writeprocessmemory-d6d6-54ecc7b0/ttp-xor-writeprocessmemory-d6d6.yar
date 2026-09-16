rule TTP_XOR_WriteProcessMemory_d6d6 {
  strings:
    $key_d6d6 = { 81 a4 [2] b3 86 [2] b5 b3 [2] 9b b3 [2] a4 af }

  condition:
    any of them
}