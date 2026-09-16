rule TTP_XOR_WriteProcessMemory_dff5 {
  strings:
    $key_dff5 = { 88 87 [2] ba a5 [2] bc 90 [2] 92 90 [2] ad 8c }

  condition:
    any of them
}