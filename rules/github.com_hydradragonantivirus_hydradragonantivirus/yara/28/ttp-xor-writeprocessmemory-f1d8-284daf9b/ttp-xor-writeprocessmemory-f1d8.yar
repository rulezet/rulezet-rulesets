rule TTP_XOR_WriteProcessMemory_f1d8 {
  strings:
    $key_f1d8 = { a6 aa [2] 94 88 [2] 92 bd [2] bc bd [2] 83 a1 }

  condition:
    any of them
}