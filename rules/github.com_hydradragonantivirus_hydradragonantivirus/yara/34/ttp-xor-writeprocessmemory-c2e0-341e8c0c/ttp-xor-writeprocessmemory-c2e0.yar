rule TTP_XOR_WriteProcessMemory_c2e0 {
  strings:
    $key_c2e0 = { 95 92 [2] a7 b0 [2] a1 85 [2] 8f 85 [2] b0 99 }

  condition:
    any of them
}