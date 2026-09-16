rule TTP_XOR_WriteProcessMemory_77d1 {
  strings:
    $key_77d1 = { 20 a3 [2] 12 81 [2] 14 b4 [2] 3a b4 [2] 05 a8 }

  condition:
    any of them
}