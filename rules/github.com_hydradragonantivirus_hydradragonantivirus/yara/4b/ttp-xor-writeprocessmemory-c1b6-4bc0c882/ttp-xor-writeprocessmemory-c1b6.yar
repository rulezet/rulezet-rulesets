rule TTP_XOR_WriteProcessMemory_c1b6 {
  strings:
    $key_c1b6 = { 96 c4 [2] a4 e6 [2] a2 d3 [2] 8c d3 [2] b3 cf }

  condition:
    any of them
}