rule TTP_XOR_WriteProcessMemory_d9d4 {
  strings:
    $key_d9d4 = { 8e a6 [2] bc 84 [2] ba b1 [2] 94 b1 [2] ab ad }

  condition:
    any of them
}