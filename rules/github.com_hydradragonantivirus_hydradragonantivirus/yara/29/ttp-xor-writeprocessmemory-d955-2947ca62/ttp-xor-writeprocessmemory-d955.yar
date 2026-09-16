rule TTP_XOR_WriteProcessMemory_d955 {
  strings:
    $key_d955 = { 8e 27 [2] bc 05 [2] ba 30 [2] 94 30 [2] ab 2c }

  condition:
    any of them
}