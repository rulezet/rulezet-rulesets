rule TTP_XOR_WriteProcessMemory_d2e6 {
  strings:
    $key_d2e6 = { 85 94 [2] b7 b6 [2] b1 83 [2] 9f 83 [2] a0 9f }

  condition:
    any of them
}