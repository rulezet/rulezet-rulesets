rule TTP_XOR_WriteProcessMemory_56c6 {
  strings:
    $key_56c6 = { 01 b4 [2] 33 96 [2] 35 a3 [2] 1b a3 [2] 24 bf }

  condition:
    any of them
}