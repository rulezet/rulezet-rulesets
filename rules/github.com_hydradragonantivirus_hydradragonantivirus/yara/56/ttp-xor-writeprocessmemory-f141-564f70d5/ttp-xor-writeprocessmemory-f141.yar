rule TTP_XOR_WriteProcessMemory_f141 {
  strings:
    $key_f141 = { a6 33 [2] 94 11 [2] 92 24 [2] bc 24 [2] 83 38 }

  condition:
    any of them
}