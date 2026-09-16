rule TTP_XOR_WriteProcessMemory_d4d4 {
  strings:
    $key_d4d4 = { 83 a6 [2] b1 84 [2] b7 b1 [2] 99 b1 [2] a6 ad }

  condition:
    any of them
}