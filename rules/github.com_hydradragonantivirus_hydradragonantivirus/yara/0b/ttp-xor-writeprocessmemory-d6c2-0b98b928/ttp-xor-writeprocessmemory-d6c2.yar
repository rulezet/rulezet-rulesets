rule TTP_XOR_WriteProcessMemory_d6c2 {
  strings:
    $key_d6c2 = { 81 b0 [2] b3 92 [2] b5 a7 [2] 9b a7 [2] a4 bb }

  condition:
    any of them
}