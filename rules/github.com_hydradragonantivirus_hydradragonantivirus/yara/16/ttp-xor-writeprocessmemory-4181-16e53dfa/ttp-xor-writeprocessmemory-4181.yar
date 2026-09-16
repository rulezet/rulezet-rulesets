rule TTP_XOR_WriteProcessMemory_4181 {
  strings:
    $key_4181 = { 16 f3 [2] 24 d1 [2] 22 e4 [2] 0c e4 [2] 33 f8 }

  condition:
    any of them
}