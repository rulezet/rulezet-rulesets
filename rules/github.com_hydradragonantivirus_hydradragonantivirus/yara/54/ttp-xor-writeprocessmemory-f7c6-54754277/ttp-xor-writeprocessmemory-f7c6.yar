rule TTP_XOR_WriteProcessMemory_f7c6 {
  strings:
    $key_f7c6 = { a0 b4 [2] 92 96 [2] 94 a3 [2] ba a3 [2] 85 bf }

  condition:
    any of them
}