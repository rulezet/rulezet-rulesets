rule TTP_XOR_WriteProcessMemory_c3a6 {
  strings:
    $key_c3a6 = { 94 d4 [2] a6 f6 [2] a0 c3 [2] 8e c3 [2] b1 df }

  condition:
    any of them
}