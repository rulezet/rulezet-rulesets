rule TTP_XOR_WriteProcessMemory_4781 {
  strings:
    $key_4781 = { 10 f3 [2] 22 d1 [2] 24 e4 [2] 0a e4 [2] 35 f8 }

  condition:
    any of them
}