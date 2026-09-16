rule TTP_XOR_WriteProcessMemory_d960 {
  strings:
    $key_d960 = { 8e 12 [2] bc 30 [2] ba 05 [2] 94 05 [2] ab 19 }

  condition:
    any of them
}