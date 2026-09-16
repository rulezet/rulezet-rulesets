rule TTP_XOR_WriteProcessMemory_f1f8 {
  strings:
    $key_f1f8 = { a6 8a [2] 94 a8 [2] 92 9d [2] bc 9d [2] 83 81 }

  condition:
    any of them
}