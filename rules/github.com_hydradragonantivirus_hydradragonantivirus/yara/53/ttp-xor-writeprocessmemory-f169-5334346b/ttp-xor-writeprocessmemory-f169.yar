rule TTP_XOR_WriteProcessMemory_f169 {
  strings:
    $key_f169 = { a6 1b [2] 94 39 [2] 92 0c [2] bc 0c [2] 83 10 }

  condition:
    any of them
}