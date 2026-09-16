rule TTP_XOR_WriteProcessMemory_7781 {
  strings:
    $key_7781 = { 20 f3 [2] 12 d1 [2] 14 e4 [2] 3a e4 [2] 05 f8 }

  condition:
    any of them
}