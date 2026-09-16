rule TTP_XOR_WriteProcessMemory_27d1 {
  strings:
    $key_27d1 = { 70 a3 [2] 42 81 [2] 44 b4 [2] 6a b4 [2] 55 a8 }

  condition:
    any of them
}