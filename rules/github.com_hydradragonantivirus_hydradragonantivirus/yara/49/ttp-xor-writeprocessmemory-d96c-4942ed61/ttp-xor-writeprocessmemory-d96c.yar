rule TTP_XOR_WriteProcessMemory_d96c {
  strings:
    $key_d96c = { 8e 1e [2] bc 3c [2] ba 09 [2] 94 09 [2] ab 15 }

  condition:
    any of them
}