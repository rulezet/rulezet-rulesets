rule TTP_XOR_WriteProcessMemory_0781 {
  strings:
    $key_0781 = { 50 f3 [2] 62 d1 [2] 64 e4 [2] 4a e4 [2] 75 f8 }

  condition:
    any of them
}