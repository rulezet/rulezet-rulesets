rule TTP_XOR_WriteProcessMemory_d9c2 {
  strings:
    $key_d9c2 = { 8e b0 [2] bc 92 [2] ba a7 [2] 94 a7 [2] ab bb }

  condition:
    any of them
}