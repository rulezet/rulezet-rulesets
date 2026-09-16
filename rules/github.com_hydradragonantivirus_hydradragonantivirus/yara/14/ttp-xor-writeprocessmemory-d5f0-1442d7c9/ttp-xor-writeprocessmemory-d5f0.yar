rule TTP_XOR_WriteProcessMemory_d5f0 {
  strings:
    $key_d5f0 = { 82 82 [2] b0 a0 [2] b6 95 [2] 98 95 [2] a7 89 }

  condition:
    any of them
}