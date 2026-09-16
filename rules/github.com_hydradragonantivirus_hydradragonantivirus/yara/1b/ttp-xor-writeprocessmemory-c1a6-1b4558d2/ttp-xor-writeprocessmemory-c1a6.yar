rule TTP_XOR_WriteProcessMemory_c1a6 {
  strings:
    $key_c1a6 = { 96 d4 [2] a4 f6 [2] a2 c3 [2] 8c c3 [2] b3 df }

  condition:
    any of them
}