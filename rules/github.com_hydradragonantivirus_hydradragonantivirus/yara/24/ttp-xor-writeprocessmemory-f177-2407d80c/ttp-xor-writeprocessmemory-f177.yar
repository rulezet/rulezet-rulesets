rule TTP_XOR_WriteProcessMemory_f177 {
  strings:
    $key_f177 = { a6 05 [2] 94 27 [2] 92 12 [2] bc 12 [2] 83 0e }

  condition:
    any of them
}