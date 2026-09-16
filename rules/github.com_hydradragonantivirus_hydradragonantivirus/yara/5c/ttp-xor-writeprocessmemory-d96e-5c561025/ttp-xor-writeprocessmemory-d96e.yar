rule TTP_XOR_WriteProcessMemory_d96e {
  strings:
    $key_d96e = { 8e 1c [2] bc 3e [2] ba 0b [2] 94 0b [2] ab 17 }

  condition:
    any of them
}