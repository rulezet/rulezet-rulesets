rule TTP_XOR_WriteProcessMemory_d9c8 {
  strings:
    $key_d9c8 = { 8e ba [2] bc 98 [2] ba ad [2] 94 ad [2] ab b1 }

  condition:
    any of them
}