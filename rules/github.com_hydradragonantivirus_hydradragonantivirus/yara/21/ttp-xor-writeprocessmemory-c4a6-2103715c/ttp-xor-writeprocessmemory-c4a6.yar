rule TTP_XOR_WriteProcessMemory_c4a6 {
  strings:
    $key_c4a6 = { 93 d4 [2] a1 f6 [2] a7 c3 [2] 89 c3 [2] b6 df }

  condition:
    any of them
}