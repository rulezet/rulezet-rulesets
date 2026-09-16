rule TTP_XOR_WriteProcessMemory_17c4 {
  strings:
    $key_17c4 = { 40 b6 [2] 72 94 [2] 74 a1 [2] 5a a1 [2] 65 bd }

  condition:
    any of them
}