rule TTP_XOR_WriteProcessMemory_d9c5 {
  strings:
    $key_d9c5 = { 8e b7 [2] bc 95 [2] ba a0 [2] 94 a0 [2] ab bc }

  condition:
    any of them
}