rule TTP_XOR_WriteProcessMemory_67c4 {
  strings:
    $key_67c4 = { 30 b6 [2] 02 94 [2] 04 a1 [2] 2a a1 [2] 15 bd }

  condition:
    any of them
}