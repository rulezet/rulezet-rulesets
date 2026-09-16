rule TTP_XOR_WriteProcessMemory_25c6 {
  strings:
    $key_25c6 = { 72 b4 [2] 40 96 [2] 46 a3 [2] 68 a3 [2] 57 bf }

  condition:
    any of them
}