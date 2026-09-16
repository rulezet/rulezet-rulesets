rule TTP_XOR_WriteProcessMemory_d9d6 {
  strings:
    $key_d9d6 = { 8e a4 [2] bc 86 [2] ba b3 [2] 94 b3 [2] ab af }

  condition:
    any of them
}