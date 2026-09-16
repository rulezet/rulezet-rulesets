rule TTP_XOR_WriteProcessMemory_d416 {
  strings:
    $key_d416 = { 83 64 [2] b1 46 [2] b7 73 [2] 99 73 [2] a6 6f }

  condition:
    any of them
}