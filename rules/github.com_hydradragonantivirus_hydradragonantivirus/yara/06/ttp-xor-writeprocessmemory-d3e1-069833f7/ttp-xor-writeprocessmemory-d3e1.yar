rule TTP_XOR_WriteProcessMemory_d3e1 {
  strings:
    $key_d3e1 = { 84 93 [2] b6 b1 [2] b0 84 [2] 9e 84 [2] a1 98 }

  condition:
    any of them
}