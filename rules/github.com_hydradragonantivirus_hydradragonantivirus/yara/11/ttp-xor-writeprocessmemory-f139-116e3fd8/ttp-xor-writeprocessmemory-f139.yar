rule TTP_XOR_WriteProcessMemory_f139 {
  strings:
    $key_f139 = { a6 4b [2] 94 69 [2] 92 5c [2] bc 5c [2] 83 40 }

  condition:
    any of them
}