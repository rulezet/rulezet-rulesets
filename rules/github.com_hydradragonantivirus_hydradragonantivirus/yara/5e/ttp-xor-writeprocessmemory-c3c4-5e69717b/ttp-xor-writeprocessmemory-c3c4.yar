rule TTP_XOR_WriteProcessMemory_c3c4 {
  strings:
    $key_c3c4 = { 94 b6 [2] a6 94 [2] a0 a1 [2] 8e a1 [2] b1 bd }

  condition:
    any of them
}