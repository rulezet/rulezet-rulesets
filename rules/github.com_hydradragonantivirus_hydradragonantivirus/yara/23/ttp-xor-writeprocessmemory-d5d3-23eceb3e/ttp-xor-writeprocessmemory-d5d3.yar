rule TTP_XOR_WriteProcessMemory_d5d3 {
  strings:
    $key_d5d3 = { 82 a1 [2] b0 83 [2] b6 b6 [2] 98 b6 [2] a7 aa }

  condition:
    any of them
}