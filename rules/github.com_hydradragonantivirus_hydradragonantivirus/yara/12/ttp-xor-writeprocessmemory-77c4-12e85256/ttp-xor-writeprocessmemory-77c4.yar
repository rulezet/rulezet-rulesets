rule TTP_XOR_WriteProcessMemory_77c4 {
  strings:
    $key_77c4 = { 20 b6 [2] 12 94 [2] 14 a1 [2] 3a a1 [2] 05 bd }

  condition:
    any of them
}