rule TTP_XOR_WriteProcessMemory_d9c3 {
  strings:
    $key_d9c3 = { 8e b1 [2] bc 93 [2] ba a6 [2] 94 a6 [2] ab ba }

  condition:
    any of them
}