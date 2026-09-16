rule TTP_XOR_WriteProcessMemory_f1ed {
  strings:
    $key_f1ed = { a6 9f [2] 94 bd [2] 92 88 [2] bc 88 [2] 83 94 }

  condition:
    any of them
}