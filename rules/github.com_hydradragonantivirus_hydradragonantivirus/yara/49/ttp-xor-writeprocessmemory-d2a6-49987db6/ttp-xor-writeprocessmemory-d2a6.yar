rule TTP_XOR_WriteProcessMemory_d2a6 {
  strings:
    $key_d2a6 = { 85 d4 [2] b7 f6 [2] b1 c3 [2] 9f c3 [2] a0 df }

  condition:
    any of them
}