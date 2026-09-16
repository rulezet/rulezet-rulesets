rule TTP_XOR_WriteProcessMemory_dffc {
  strings:
    $key_dffc = { 88 8e [2] ba ac [2] bc 99 [2] 92 99 [2] ad 85 }

  condition:
    any of them
}