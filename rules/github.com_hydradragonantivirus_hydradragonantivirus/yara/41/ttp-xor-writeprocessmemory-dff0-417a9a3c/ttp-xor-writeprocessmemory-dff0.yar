rule TTP_XOR_WriteProcessMemory_dff0 {
  strings:
    $key_dff0 = { 88 82 [2] ba a0 [2] bc 95 [2] 92 95 [2] ad 89 }

  condition:
    any of them
}