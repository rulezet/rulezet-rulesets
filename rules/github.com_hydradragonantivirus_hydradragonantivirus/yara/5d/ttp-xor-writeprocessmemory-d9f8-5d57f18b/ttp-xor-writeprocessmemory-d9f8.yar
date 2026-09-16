rule TTP_XOR_WriteProcessMemory_d9f8 {
  strings:
    $key_d9f8 = { 8e 8a [2] bc a8 [2] ba 9d [2] 94 9d [2] ab 81 }

  condition:
    any of them
}