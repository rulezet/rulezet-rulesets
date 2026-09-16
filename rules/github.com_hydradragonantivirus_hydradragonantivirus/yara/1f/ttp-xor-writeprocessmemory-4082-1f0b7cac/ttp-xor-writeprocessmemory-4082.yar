rule TTP_XOR_WriteProcessMemory_4082 {
  strings:
    $key_4082 = { 17 f0 [2] 25 d2 [2] 23 e7 [2] 0d e7 [2] 32 fb }

  condition:
    any of them
}