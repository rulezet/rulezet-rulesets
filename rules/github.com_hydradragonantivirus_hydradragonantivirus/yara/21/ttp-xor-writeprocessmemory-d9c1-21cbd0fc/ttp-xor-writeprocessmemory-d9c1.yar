rule TTP_XOR_WriteProcessMemory_d9c1 {
  strings:
    $key_d9c1 = { 8e b3 [2] bc 91 [2] ba a4 [2] 94 a4 [2] ab b8 }

  condition:
    any of them
}