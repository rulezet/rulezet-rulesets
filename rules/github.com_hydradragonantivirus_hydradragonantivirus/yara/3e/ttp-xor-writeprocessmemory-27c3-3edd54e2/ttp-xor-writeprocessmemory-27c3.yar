rule TTP_XOR_WriteProcessMemory_27c3 {
  strings:
    $key_27c3 = { 70 b1 [2] 42 93 [2] 44 a6 [2] 6a a6 [2] 55 ba }

  condition:
    any of them
}