rule TTP_XOR_WriteProcessMemory_d91e {
  strings:
    $key_d91e = { 8e 6c [2] bc 4e [2] ba 7b [2] 94 7b [2] ab 67 }

  condition:
    any of them
}