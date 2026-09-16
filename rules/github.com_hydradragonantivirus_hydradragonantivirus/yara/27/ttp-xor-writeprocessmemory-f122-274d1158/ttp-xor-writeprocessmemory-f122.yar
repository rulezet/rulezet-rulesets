rule TTP_XOR_WriteProcessMemory_f122 {
  strings:
    $key_f122 = { a6 50 [2] 94 72 [2] 92 47 [2] bc 47 [2] 83 5b }

  condition:
    any of them
}