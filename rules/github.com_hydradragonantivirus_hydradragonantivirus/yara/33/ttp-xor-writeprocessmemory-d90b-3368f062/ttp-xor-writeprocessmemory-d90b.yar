rule TTP_XOR_WriteProcessMemory_d90b {
  strings:
    $key_d90b = { 8e 79 [2] bc 5b [2] ba 6e [2] 94 6e [2] ab 72 }

  condition:
    any of them
}