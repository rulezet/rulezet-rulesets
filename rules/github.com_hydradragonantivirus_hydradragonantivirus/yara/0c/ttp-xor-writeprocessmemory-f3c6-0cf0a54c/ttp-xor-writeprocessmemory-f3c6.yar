rule TTP_XOR_WriteProcessMemory_f3c6 {
  strings:
    $key_f3c6 = { a4 b4 [2] 96 96 [2] 90 a3 [2] be a3 [2] 81 bf }

  condition:
    any of them
}