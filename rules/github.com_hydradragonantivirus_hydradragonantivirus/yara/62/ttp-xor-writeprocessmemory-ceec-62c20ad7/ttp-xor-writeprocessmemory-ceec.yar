rule TTP_XOR_WriteProcessMemory_ceec {
  strings:
    $key_ceec = { 99 9e [2] ab bc [2] ad 89 [2] 83 89 [2] bc 95 }

  condition:
    any of them
}