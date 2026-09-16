rule TTP_XOR_WriteProcessMemory_56c4 {
  strings:
    $key_56c4 = { 01 b6 [2] 33 94 [2] 35 a1 [2] 1b a1 [2] 24 bd }

  condition:
    any of them
}