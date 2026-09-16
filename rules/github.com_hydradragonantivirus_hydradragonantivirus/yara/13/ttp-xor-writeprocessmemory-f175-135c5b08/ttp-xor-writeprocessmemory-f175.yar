rule TTP_XOR_WriteProcessMemory_f175 {
  strings:
    $key_f175 = { a6 07 [2] 94 25 [2] 92 10 [2] bc 10 [2] 83 0c }

  condition:
    any of them
}