rule TTP_XOR_WriteProcessMemory_d97b {
  strings:
    $key_d97b = { 8e 09 [2] bc 2b [2] ba 1e [2] 94 1e [2] ab 02 }

  condition:
    any of them
}