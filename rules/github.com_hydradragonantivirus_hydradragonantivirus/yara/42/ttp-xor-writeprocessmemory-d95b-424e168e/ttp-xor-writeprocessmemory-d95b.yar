rule TTP_XOR_WriteProcessMemory_d95b {
  strings:
    $key_d95b = { 8e 29 [2] bc 0b [2] ba 3e [2] 94 3e [2] ab 22 }

  condition:
    any of them
}