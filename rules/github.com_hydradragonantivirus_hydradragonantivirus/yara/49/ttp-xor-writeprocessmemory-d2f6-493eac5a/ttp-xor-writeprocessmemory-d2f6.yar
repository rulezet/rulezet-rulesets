rule TTP_XOR_WriteProcessMemory_d2f6 {
  strings:
    $key_d2f6 = { 85 84 [2] b7 a6 [2] b1 93 [2] 9f 93 [2] a0 8f }

  condition:
    any of them
}