rule TTP_XOR_WriteProcessMemory_dff6 {
  strings:
    $key_dff6 = { 88 84 [2] ba a6 [2] bc 93 [2] 92 93 [2] ad 8f }

  condition:
    any of them
}