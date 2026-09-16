rule TTP_XOR_WriteProcessMemory_d96f {
  strings:
    $key_d96f = { 8e 1d [2] bc 3f [2] ba 0a [2] 94 0a [2] ab 16 }

  condition:
    any of them
}