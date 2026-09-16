rule TTP_XOR_WriteProcessMemory_f135 {
  strings:
    $key_f135 = { a6 47 [2] 94 65 [2] 92 50 [2] bc 50 [2] 83 4c }

  condition:
    any of them
}