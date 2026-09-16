rule TTP_XOR_WriteProcessMemory_f117 {
  strings:
    $key_f117 = { a6 65 [2] 94 47 [2] 92 72 [2] bc 72 [2] 83 6e }

  condition:
    any of them
}