rule TTP_XOR_WriteProcessMemory_f5c6 {
  strings:
    $key_f5c6 = { a2 b4 [2] 90 96 [2] 96 a3 [2] b8 a3 [2] 87 bf }

  condition:
    any of them
}