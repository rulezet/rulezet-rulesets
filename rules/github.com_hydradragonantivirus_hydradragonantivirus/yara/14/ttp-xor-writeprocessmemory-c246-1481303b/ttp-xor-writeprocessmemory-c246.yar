rule TTP_XOR_WriteProcessMemory_c246 {
  strings:
    $key_c246 = { 95 34 [2] a7 16 [2] a1 23 [2] 8f 23 [2] b0 3f }

  condition:
    any of them
}