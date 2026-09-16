rule TTP_XOR_WriteProcessMemory_f745 {
  strings:
    $key_f745 = { a0 37 [2] 92 15 [2] 94 20 [2] ba 20 [2] 85 3c }

  condition:
    any of them
}