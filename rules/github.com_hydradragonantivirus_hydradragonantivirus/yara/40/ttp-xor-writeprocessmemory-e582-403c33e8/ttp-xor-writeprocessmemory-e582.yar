rule TTP_XOR_WriteProcessMemory_e582 {
  strings:
    $key_e582 = { b2 f0 [2] 80 d2 [2] 86 e7 [2] a8 e7 [2] 97 fb }

  condition:
    any of them
}