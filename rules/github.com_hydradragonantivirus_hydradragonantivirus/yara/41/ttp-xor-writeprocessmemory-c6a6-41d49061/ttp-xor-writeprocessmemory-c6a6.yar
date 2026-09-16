rule TTP_XOR_WriteProcessMemory_c6a6 {
  strings:
    $key_c6a6 = { 91 d4 [2] a3 f6 [2] a5 c3 [2] 8b c3 [2] b4 df }

  condition:
    any of them
}