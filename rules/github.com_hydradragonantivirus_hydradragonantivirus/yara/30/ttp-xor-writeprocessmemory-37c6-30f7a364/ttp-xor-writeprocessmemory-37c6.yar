rule TTP_XOR_WriteProcessMemory_37c6 {
  strings:
    $key_37c6 = { 60 b4 [2] 52 96 [2] 54 a3 [2] 7a a3 [2] 45 bf }

  condition:
    any of them
}