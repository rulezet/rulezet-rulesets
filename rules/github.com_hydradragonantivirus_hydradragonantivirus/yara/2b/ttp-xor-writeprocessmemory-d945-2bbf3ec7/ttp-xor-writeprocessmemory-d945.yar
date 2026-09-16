rule TTP_XOR_WriteProcessMemory_d945 {
  strings:
    $key_d945 = { 8e 37 [2] bc 15 [2] ba 20 [2] 94 20 [2] ab 3c }

  condition:
    any of them
}