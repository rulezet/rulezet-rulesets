rule TTP_XOR_WriteProcessMemory_d9f5 {
  strings:
    $key_d9f5 = { 8e 87 [2] bc a5 [2] ba 90 [2] 94 90 [2] ab 8c }

  condition:
    any of them
}