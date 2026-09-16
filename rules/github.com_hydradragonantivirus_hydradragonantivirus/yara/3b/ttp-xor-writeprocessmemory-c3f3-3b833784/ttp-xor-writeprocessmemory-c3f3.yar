rule TTP_XOR_WriteProcessMemory_c3f3 {
  strings:
    $key_c3f3 = { 94 81 [2] a6 a3 [2] a0 96 [2] 8e 96 [2] b1 8a }

  condition:
    any of them
}