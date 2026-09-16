rule TTP_XOR_WriteProcessMemory_27d4 {
  strings:
    $key_27d4 = { 70 a6 [2] 42 84 [2] 44 b1 [2] 6a b1 [2] 55 ad }

  condition:
    any of them
}