rule TTP_XOR_WriteProcessMemory_dfcc {
  strings:
    $key_dfcc = { 88 be [2] ba 9c [2] bc a9 [2] 92 a9 [2] ad b5 }

  condition:
    any of them
}