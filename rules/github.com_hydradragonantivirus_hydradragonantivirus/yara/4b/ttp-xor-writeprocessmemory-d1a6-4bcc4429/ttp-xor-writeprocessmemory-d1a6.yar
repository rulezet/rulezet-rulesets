rule TTP_XOR_WriteProcessMemory_d1a6 {
  strings:
    $key_d1a6 = { 86 d4 [2] b4 f6 [2] b2 c3 [2] 9c c3 [2] a3 df }

  condition:
    any of them
}