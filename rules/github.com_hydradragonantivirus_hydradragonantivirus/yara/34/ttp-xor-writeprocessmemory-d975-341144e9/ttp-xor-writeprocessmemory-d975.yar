rule TTP_XOR_WriteProcessMemory_d975 {
  strings:
    $key_d975 = { 8e 07 [2] bc 25 [2] ba 10 [2] 94 10 [2] ab 0c }

  condition:
    any of them
}