rule TTP_XOR_WriteProcessMemory_f161 {
  strings:
    $key_f161 = { a6 13 [2] 94 31 [2] 92 04 [2] bc 04 [2] 83 18 }

  condition:
    any of them
}