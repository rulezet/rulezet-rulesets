rule TTP_XOR_WriteProcessMemory_c5b6 {
  strings:
    $key_c5b6 = { 92 c4 [2] a0 e6 [2] a6 d3 [2] 88 d3 [2] b7 cf }

  condition:
    any of them
}