rule TTP_XOR_WriteProcessMemory_f119 {
  strings:
    $key_f119 = { a6 6b [2] 94 49 [2] 92 7c [2] bc 7c [2] 83 60 }

  condition:
    any of them
}