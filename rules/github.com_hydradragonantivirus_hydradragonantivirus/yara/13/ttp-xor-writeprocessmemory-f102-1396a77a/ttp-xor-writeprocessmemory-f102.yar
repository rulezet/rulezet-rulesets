rule TTP_XOR_WriteProcessMemory_f102 {
  strings:
    $key_f102 = { a6 70 [2] 94 52 [2] 92 67 [2] bc 67 [2] 83 7b }

  condition:
    any of them
}