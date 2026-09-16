rule TTP_XOR_WriteProcessMemory_c7a6 {
  strings:
    $key_c7a6 = { 90 d4 [2] a2 f6 [2] a4 c3 [2] 8a c3 [2] b5 df }

  condition:
    any of them
}