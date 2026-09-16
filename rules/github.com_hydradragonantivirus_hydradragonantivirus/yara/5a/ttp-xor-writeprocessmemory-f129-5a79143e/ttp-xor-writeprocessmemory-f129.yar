rule TTP_XOR_WriteProcessMemory_f129 {
  strings:
    $key_f129 = { a6 5b [2] 94 79 [2] 92 4c [2] bc 4c [2] 83 50 }

  condition:
    any of them
}