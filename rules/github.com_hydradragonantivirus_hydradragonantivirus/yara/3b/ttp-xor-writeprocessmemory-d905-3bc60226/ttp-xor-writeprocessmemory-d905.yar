rule TTP_XOR_WriteProcessMemory_d905 {
  strings:
    $key_d905 = { 8e 77 [2] bc 55 [2] ba 60 [2] 94 60 [2] ab 7c }

  condition:
    any of them
}