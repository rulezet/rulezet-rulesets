rule TTP_XOR_WriteProcessMemory_d9c7 {
  strings:
    $key_d9c7 = { 8e b5 [2] bc 97 [2] ba a2 [2] 94 a2 [2] ab be }

  condition:
    any of them
}