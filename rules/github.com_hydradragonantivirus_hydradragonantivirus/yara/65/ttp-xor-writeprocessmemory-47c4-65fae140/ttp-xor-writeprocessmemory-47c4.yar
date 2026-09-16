rule TTP_XOR_WriteProcessMemory_47c4 {
  strings:
    $key_47c4 = { 10 b6 [2] 22 94 [2] 24 a1 [2] 0a a1 [2] 35 bd }

  condition:
    any of them
}