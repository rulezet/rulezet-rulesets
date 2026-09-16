rule TTP_XOR_WriteProcessMemory_dfe2 {
  strings:
    $key_dfe2 = { 88 90 [2] ba b2 [2] bc 87 [2] 92 87 [2] ad 9b }

  condition:
    any of them
}