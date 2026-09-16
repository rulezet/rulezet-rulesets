rule TTP_XOR_WriteProcessMemory_f123 {
  strings:
    $key_f123 = { a6 51 [2] 94 73 [2] 92 46 [2] bc 46 [2] 83 5a }

  condition:
    any of them
}