rule TTP_XOR_WriteProcessMemory_53c6 {
  strings:
    $key_53c6 = { 04 b4 [2] 36 96 [2] 30 a3 [2] 1e a3 [2] 21 bf }

  condition:
    any of them
}