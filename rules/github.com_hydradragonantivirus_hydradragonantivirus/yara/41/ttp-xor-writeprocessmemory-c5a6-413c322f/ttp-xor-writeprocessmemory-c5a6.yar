rule TTP_XOR_WriteProcessMemory_c5a6 {
  strings:
    $key_c5a6 = { 92 d4 [2] a0 f6 [2] a6 c3 [2] 88 c3 [2] b7 df }

  condition:
    any of them
}