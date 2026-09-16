rule TTP_XOR_WriteProcessMemory_f1fc {
  strings:
    $key_f1fc = { a6 8e [2] 94 ac [2] 92 99 [2] bc 99 [2] 83 85 }

  condition:
    any of them
}