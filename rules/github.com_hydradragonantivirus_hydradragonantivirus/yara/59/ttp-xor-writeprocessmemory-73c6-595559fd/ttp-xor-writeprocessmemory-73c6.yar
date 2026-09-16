rule TTP_XOR_WriteProcessMemory_73c6 {
  strings:
    $key_73c6 = { 24 b4 [2] 16 96 [2] 10 a3 [2] 3e a3 [2] 01 bf }

  condition:
    any of them
}