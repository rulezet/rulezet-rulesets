rule TTP_XOR_WriteProcessMemory_f130 {
  strings:
    $key_f130 = { a6 42 [2] 94 60 [2] 92 55 [2] bc 55 [2] 83 49 }

  condition:
    any of them
}