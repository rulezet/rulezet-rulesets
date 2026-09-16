rule TTP_XOR_WriteProcessMemory_d5f6 {
  strings:
    $key_d5f6 = { 82 84 [2] b0 a6 [2] b6 93 [2] 98 93 [2] a7 8f }

  condition:
    any of them
}