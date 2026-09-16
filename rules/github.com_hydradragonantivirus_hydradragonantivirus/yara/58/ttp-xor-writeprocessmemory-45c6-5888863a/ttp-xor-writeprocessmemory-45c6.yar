rule TTP_XOR_WriteProcessMemory_45c6 {
  strings:
    $key_45c6 = { 12 b4 [2] 20 96 [2] 26 a3 [2] 08 a3 [2] 37 bf }

  condition:
    any of them
}