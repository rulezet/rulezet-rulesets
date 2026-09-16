rule TTP_XOR_WriteProcessMemory_d94e {
  strings:
    $key_d94e = { 8e 3c [2] bc 1e [2] ba 2b [2] 94 2b [2] ab 37 }

  condition:
    any of them
}