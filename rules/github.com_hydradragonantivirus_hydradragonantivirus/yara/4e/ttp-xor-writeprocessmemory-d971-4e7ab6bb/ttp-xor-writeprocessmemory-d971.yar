rule TTP_XOR_WriteProcessMemory_d971 {
  strings:
    $key_d971 = { 8e 03 [2] bc 21 [2] ba 14 [2] 94 14 [2] ab 08 }

  condition:
    any of them
}