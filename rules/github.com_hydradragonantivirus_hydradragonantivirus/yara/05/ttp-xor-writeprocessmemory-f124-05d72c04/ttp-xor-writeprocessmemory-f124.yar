rule TTP_XOR_WriteProcessMemory_f124 {
  strings:
    $key_f124 = { a6 56 [2] 94 74 [2] 92 41 [2] bc 41 [2] 83 5d }

  condition:
    any of them
}