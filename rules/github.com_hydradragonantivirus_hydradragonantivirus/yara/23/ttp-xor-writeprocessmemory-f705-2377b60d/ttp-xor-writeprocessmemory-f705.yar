rule TTP_XOR_WriteProcessMemory_f705 {
  strings:
    $key_f705 = { a0 77 [2] 92 55 [2] 94 60 [2] ba 60 [2] 85 7c }

  condition:
    any of them
}