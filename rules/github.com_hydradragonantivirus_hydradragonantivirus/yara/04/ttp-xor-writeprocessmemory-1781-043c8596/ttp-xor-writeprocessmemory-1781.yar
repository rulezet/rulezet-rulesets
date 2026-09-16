rule TTP_XOR_WriteProcessMemory_1781 {
  strings:
    $key_1781 = { 40 f3 [2] 72 d1 [2] 74 e4 [2] 5a e4 [2] 65 f8 }

  condition:
    any of them
}