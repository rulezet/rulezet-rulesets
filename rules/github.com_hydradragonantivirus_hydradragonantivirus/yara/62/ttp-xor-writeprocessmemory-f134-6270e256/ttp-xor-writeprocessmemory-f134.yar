rule TTP_XOR_WriteProcessMemory_f134 {
  strings:
    $key_f134 = { a6 46 [2] 94 64 [2] 92 51 [2] bc 51 [2] 83 4d }

  condition:
    any of them
}