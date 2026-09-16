rule TTP_XOR_WriteProcessMemory_f137 {
  strings:
    $key_f137 = { a6 45 [2] 94 67 [2] 92 52 [2] bc 52 [2] 83 4e }

  condition:
    any of them
}