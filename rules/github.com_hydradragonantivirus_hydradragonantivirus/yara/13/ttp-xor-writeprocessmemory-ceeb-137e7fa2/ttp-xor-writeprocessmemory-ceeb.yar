rule TTP_XOR_WriteProcessMemory_ceeb {
  strings:
    $key_ceeb = { 99 99 [2] ab bb [2] ad 8e [2] 83 8e [2] bc 92 }

  condition:
    any of them
}