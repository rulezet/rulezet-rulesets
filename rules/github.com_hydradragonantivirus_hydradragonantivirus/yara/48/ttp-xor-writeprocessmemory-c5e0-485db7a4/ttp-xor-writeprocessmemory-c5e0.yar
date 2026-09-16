rule TTP_XOR_WriteProcessMemory_c5e0 {
  strings:
    $key_c5e0 = { 92 92 [2] a0 b0 [2] a6 85 [2] 88 85 [2] b7 99 }

  condition:
    any of them
}