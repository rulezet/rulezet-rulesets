rule TTP_XOR_WriteProcessMemory_74c6 {
  strings:
    $key_74c6 = { 23 b4 [2] 11 96 [2] 17 a3 [2] 39 a3 [2] 06 bf }

  condition:
    any of them
}