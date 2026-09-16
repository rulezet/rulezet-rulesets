rule TTP_XOR_WriteProcessMemory_17c6 {
  strings:
    $key_17c6 = { 40 b4 [2] 72 96 [2] 74 a3 [2] 5a a3 [2] 65 bf }

  condition:
    any of them
}