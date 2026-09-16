rule TTP_XOR_WriteProcessMemory_f149 {
  strings:
    $key_f149 = { a6 3b [2] 94 19 [2] 92 2c [2] bc 2c [2] 83 30 }

  condition:
    any of them
}