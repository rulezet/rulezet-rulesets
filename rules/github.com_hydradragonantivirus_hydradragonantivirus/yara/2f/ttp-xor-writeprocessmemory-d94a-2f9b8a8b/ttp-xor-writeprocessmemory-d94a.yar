rule TTP_XOR_WriteProcessMemory_d94a {
  strings:
    $key_d94a = { 8e 38 [2] bc 1a [2] ba 2f [2] 94 2f [2] ab 33 }

  condition:
    any of them
}