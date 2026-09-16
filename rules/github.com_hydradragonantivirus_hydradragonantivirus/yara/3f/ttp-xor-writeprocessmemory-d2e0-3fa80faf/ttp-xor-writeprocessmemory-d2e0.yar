rule TTP_XOR_WriteProcessMemory_d2e0 {
  strings:
    $key_d2e0 = { 85 92 [2] b7 b0 [2] b1 85 [2] 9f 85 [2] a0 99 }

  condition:
    any of them
}