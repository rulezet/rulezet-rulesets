rule TTP_XOR_WriteProcessMemory_4ac6 {
  strings:
    $key_4ac6 = { 1d b4 [2] 2f 96 [2] 29 a3 [2] 07 a3 [2] 38 bf }

  condition:
    any of them
}