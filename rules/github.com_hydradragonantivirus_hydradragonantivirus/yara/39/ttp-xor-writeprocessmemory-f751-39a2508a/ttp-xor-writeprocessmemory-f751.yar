rule TTP_XOR_WriteProcessMemory_f751 {
  strings:
    $key_f751 = { a0 23 [2] 92 01 [2] 94 34 [2] ba 34 [2] 85 28 }

  condition:
    any of them
}