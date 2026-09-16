rule TTP_XOR_WriteProcessMemory_27c7 {
  strings:
    $key_27c7 = { 70 b5 [2] 42 97 [2] 44 a2 [2] 6a a2 [2] 55 be }

  condition:
    any of them
}