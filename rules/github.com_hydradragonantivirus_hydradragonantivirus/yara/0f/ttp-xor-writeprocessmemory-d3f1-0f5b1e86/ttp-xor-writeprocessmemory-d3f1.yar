rule TTP_XOR_WriteProcessMemory_d3f1 {
  strings:
    $key_d3f1 = { 84 83 [2] b6 a1 [2] b0 94 [2] 9e 94 [2] a1 88 }

  condition:
    any of them
}