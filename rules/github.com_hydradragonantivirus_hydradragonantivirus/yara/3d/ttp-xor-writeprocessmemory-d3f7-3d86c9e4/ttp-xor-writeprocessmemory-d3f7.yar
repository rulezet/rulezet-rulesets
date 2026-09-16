rule TTP_XOR_WriteProcessMemory_d3f7 {
  strings:
    $key_d3f7 = { 84 85 [2] b6 a7 [2] b0 92 [2] 9e 92 [2] a1 8e }

  condition:
    any of them
}