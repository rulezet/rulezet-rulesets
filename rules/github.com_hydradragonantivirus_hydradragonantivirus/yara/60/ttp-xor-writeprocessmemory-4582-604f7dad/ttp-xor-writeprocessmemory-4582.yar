rule TTP_XOR_WriteProcessMemory_4582 {
  strings:
    $key_4582 = { 12 f0 [2] 20 d2 [2] 26 e7 [2] 08 e7 [2] 37 fb }

  condition:
    any of them
}