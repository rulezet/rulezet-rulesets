rule TTP_XOR_WriteProcessMemory_27c4 {
  strings:
    $key_27c4 = { 70 b6 [2] 42 94 [2] 44 a1 [2] 6a a1 [2] 55 bd }

  condition:
    any of them
}