rule TTP_XOR_WriteProcessMemory_d953 {
  strings:
    $key_d953 = { 8e 21 [2] bc 03 [2] ba 36 [2] 94 36 [2] ab 2a }

  condition:
    any of them
}