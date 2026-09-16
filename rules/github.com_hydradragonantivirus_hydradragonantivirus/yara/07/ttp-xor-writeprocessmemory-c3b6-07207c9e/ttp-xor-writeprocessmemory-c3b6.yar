rule TTP_XOR_WriteProcessMemory_c3b6 {
  strings:
    $key_c3b6 = { 94 c4 [2] a6 e6 [2] a0 d3 [2] 8e d3 [2] b1 cf }

  condition:
    any of them
}