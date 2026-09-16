rule TTP_XOR_WriteProcessMemory_f15b {
  strings:
    $key_f15b = { a6 29 [2] 94 0b [2] 92 3e [2] bc 3e [2] 83 22 }

  condition:
    any of them
}