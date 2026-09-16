rule TTP_XOR_WriteProcessMemory_f132 {
  strings:
    $key_f132 = { a6 40 [2] 94 62 [2] 92 57 [2] bc 57 [2] 83 4b }

  condition:
    any of them
}