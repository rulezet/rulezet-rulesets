rule TTP_XOR_WriteProcessMemory_c6c2 {
  strings:
    $key_c6c2 = { 91 b0 [2] a3 92 [2] a5 a7 [2] 8b a7 [2] b4 bb }

  condition:
    any of them
}