rule TTP_XOR_WriteProcessMemory_d4d3 {
  strings:
    $key_d4d3 = { 83 a1 [2] b1 83 [2] b7 b6 [2] 99 b6 [2] a6 aa }

  condition:
    any of them
}