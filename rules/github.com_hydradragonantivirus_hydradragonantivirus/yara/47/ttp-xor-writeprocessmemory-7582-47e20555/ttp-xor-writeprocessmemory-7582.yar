rule TTP_XOR_WriteProcessMemory_7582 {
  strings:
    $key_7582 = { 22 f0 [2] 10 d2 [2] 16 e7 [2] 38 e7 [2] 07 fb }

  condition:
    any of them
}