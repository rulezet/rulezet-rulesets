rule TTP_XOR_WriteProcessMemory_d97e {
  strings:
    $key_d97e = { 8e 0c [2] bc 2e [2] ba 1b [2] 94 1b [2] ab 07 }

  condition:
    any of them
}