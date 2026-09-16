rule TTP_XOR_WriteProcessMemory_f1c6 {
  strings:
    $key_f1c6 = { a6 b4 [2] 94 96 [2] 92 a3 [2] bc a3 [2] 83 bf }

  condition:
    any of them
}