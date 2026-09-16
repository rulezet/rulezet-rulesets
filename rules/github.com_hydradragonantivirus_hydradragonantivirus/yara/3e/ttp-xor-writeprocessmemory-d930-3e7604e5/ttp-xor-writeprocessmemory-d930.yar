rule TTP_XOR_WriteProcessMemory_d930 {
  strings:
    $key_d930 = { 8e 42 [2] bc 60 [2] ba 55 [2] 94 55 [2] ab 49 }

  condition:
    any of them
}