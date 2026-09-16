rule TTP_XOR_WriteProcessMemory_d928 {
  strings:
    $key_d928 = { 8e 5a [2] bc 78 [2] ba 4d [2] 94 4d [2] ab 51 }

  condition:
    any of them
}