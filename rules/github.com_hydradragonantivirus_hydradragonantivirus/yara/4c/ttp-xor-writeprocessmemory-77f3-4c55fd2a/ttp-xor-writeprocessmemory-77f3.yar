rule TTP_XOR_WriteProcessMemory_77f3 {
  strings:
    $key_77f3 = { 20 81 [2] 12 a3 [2] 14 96 [2] 3a 96 [2] 05 8a }

  condition:
    any of them
}