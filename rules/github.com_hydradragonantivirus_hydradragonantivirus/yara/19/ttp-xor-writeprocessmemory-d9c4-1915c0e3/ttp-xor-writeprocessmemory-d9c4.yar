rule TTP_XOR_WriteProcessMemory_d9c4 {
  strings:
    $key_d9c4 = { 8e b6 [2] bc 94 [2] ba a1 [2] 94 a1 [2] ab bd }

  condition:
    any of them
}