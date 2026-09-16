rule TTP_XOR_WriteProcessMemory_dfe7 {
  strings:
    $key_dfe7 = { 88 95 [2] ba b7 [2] bc 82 [2] 92 82 [2] ad 9e }

  condition:
    any of them
}