rule TTP_XOR_WriteProcessMemory_27f6 {
  strings:
    $key_27f6 = { 70 84 [2] 42 a6 [2] 44 93 [2] 6a 93 [2] 55 8f }

  condition:
    any of them
}