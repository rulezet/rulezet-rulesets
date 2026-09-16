rule TTP_XOR_WriteProcessMemory_5ac6 {
  strings:
    $key_5ac6 = { 0d b4 [2] 3f 96 [2] 39 a3 [2] 17 a3 [2] 28 bf }

  condition:
    any of them
}