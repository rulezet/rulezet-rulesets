rule TTP_XOR_WriteProcessMemory_f170 {
  strings:
    $key_f170 = { a6 02 [2] 94 20 [2] 92 15 [2] bc 15 [2] 83 09 }

  condition:
    any of them
}