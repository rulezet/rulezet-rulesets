rule TTP_XOR_WriteProcessMemory_3781 {
  strings:
    $key_3781 = { 60 f3 [2] 52 d1 [2] 54 e4 [2] 7a e4 [2] 45 f8 }

  condition:
    any of them
}