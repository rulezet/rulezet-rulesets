rule TTP_XOR_WriteProcessMemory_27f2 {
  strings:
    $key_27f2 = { 70 80 [2] 42 a2 [2] 44 97 [2] 6a 97 [2] 55 8b }

  condition:
    any of them
}