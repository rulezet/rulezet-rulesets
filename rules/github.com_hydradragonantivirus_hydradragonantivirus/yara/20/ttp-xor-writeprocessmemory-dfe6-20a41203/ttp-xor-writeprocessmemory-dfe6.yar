rule TTP_XOR_WriteProcessMemory_dfe6 {
  strings:
    $key_dfe6 = { 88 94 [2] ba b6 [2] bc 83 [2] 92 83 [2] ad 9f }

  condition:
    any of them
}