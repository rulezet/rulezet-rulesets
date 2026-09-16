rule TTP_XOR_WriteProcessMemory_c582 {
  strings:
    $key_c582 = { 92 f0 [2] a0 d2 [2] a6 e7 [2] 88 e7 [2] b7 fb }

  condition:
    any of them
}