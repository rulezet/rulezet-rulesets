rule TTP_XOR_WriteProcessMemory_f7f3 {
  strings:
    $key_f7f3 = { a0 81 [2] 92 a3 [2] 94 96 [2] ba 96 [2] 85 8a }

  condition:
    any of them
}