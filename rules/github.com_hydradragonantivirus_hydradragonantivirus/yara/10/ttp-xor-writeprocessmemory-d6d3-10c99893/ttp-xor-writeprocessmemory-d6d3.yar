rule TTP_XOR_WriteProcessMemory_d6d3 {
  strings:
    $key_d6d3 = { 81 a1 [2] b3 83 [2] b5 b6 [2] 9b b6 [2] a4 aa }

  condition:
    any of them
}