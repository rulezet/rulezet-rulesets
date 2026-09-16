rule TTP_XOR_WriteProcessMemory_c4d4 {
  strings:
    $key_c4d4 = { 93 a6 [2] a1 84 [2] a7 b1 [2] 89 b1 [2] b6 ad }

  condition:
    any of them
}