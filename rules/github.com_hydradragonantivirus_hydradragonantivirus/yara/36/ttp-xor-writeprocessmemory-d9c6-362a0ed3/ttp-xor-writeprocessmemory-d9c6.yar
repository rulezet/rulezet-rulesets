rule TTP_XOR_WriteProcessMemory_d9c6 {
  strings:
    $key_d9c6 = { 8e b4 [2] bc 96 [2] ba a3 [2] 94 a3 [2] ab bf }

  condition:
    any of them
}