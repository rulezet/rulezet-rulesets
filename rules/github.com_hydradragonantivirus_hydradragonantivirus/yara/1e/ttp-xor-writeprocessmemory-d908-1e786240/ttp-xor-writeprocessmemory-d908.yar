rule TTP_XOR_WriteProcessMemory_d908 {
  strings:
    $key_d908 = { 8e 7a [2] bc 58 [2] ba 6d [2] 94 6d [2] ab 71 }

  condition:
    any of them
}