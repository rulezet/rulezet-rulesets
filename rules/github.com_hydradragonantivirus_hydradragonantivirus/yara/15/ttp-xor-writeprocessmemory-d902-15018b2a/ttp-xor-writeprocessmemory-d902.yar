rule TTP_XOR_WriteProcessMemory_d902 {
  strings:
    $key_d902 = { 8e 70 [2] bc 52 [2] ba 67 [2] 94 67 [2] ab 7b }

  condition:
    any of them
}