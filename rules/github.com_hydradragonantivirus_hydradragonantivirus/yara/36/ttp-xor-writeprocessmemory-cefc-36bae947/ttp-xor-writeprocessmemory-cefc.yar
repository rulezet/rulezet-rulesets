rule TTP_XOR_WriteProcessMemory_cefc {
  strings:
    $key_cefc = { 99 8e [2] ab ac [2] ad 99 [2] 83 99 [2] bc 85 }

  condition:
    any of them
}