rule TTP_XOR_WriteProcessMemory_67c6 {
  strings:
    $key_67c6 = { 30 b4 [2] 02 96 [2] 04 a3 [2] 2a a3 [2] 15 bf }

  condition:
    any of them
}