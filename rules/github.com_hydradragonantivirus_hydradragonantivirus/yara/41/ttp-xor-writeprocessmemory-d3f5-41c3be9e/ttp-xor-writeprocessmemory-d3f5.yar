rule TTP_XOR_WriteProcessMemory_d3f5 {
  strings:
    $key_d3f5 = { 84 87 [2] b6 a5 [2] b0 90 [2] 9e 90 [2] a1 8c }

  condition:
    any of them
}