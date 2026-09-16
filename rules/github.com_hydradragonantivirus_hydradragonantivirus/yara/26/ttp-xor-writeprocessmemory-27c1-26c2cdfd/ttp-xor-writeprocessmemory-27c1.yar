rule TTP_XOR_WriteProcessMemory_27c1 {
  strings:
    $key_27c1 = { 70 b3 [2] 42 91 [2] 44 a4 [2] 6a a4 [2] 55 b8 }

  condition:
    any of them
}