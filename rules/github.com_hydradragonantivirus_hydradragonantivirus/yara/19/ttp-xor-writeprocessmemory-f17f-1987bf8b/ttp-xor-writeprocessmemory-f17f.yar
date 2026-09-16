rule TTP_XOR_WriteProcessMemory_f17f {
  strings:
    $key_f17f = { a6 0d [2] 94 2f [2] 92 1a [2] bc 1a [2] 83 06 }

  condition:
    any of them
}