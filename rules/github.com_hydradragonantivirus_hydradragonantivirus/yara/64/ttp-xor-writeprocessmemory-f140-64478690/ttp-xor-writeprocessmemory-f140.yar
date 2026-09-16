rule TTP_XOR_WriteProcessMemory_f140 {
  strings:
    $key_f140 = { a6 32 [2] 94 10 [2] 92 25 [2] bc 25 [2] 83 39 }

  condition:
    any of them
}