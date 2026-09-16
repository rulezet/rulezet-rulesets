rule TTP_XOR_WriteProcessMemory_c4f3 {
  strings:
    $key_c4f3 = { 93 81 [2] a1 a3 [2] a7 96 [2] 89 96 [2] b6 8a }

  condition:
    any of them
}