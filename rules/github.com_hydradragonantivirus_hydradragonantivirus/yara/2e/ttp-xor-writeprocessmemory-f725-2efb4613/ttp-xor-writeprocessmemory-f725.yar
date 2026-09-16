rule TTP_XOR_WriteProcessMemory_f725 {
  strings:
    $key_f725 = { a0 57 [2] 92 75 [2] 94 40 [2] ba 40 [2] 85 5c }

  condition:
    any of them
}