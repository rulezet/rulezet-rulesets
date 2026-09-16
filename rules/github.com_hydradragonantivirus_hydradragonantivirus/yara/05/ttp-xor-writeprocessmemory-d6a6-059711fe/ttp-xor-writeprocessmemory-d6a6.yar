rule TTP_XOR_WriteProcessMemory_d6a6 {
  strings:
    $key_d6a6 = { 81 d4 [2] b3 f6 [2] b5 c3 [2] 9b c3 [2] a4 df }

  condition:
    any of them
}