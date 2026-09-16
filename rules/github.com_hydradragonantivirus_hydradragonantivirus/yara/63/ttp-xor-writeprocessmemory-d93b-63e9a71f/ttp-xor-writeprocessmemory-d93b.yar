rule TTP_XOR_WriteProcessMemory_d93b {
  strings:
    $key_d93b = { 8e 49 [2] bc 6b [2] ba 5e [2] 94 5e [2] ab 42 }

  condition:
    any of them
}