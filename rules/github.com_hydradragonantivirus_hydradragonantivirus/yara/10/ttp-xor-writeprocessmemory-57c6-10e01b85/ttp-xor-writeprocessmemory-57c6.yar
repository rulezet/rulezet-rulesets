rule TTP_XOR_WriteProcessMemory_57c6 {
  strings:
    $key_57c6 = { 00 b4 [2] 32 96 [2] 34 a3 [2] 1a a3 [2] 25 bf }

  condition:
    any of them
}