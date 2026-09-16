rule TTP_XOR_WriteProcessMemory_d9d5 {
  strings:
    $key_d9d5 = { 8e a7 [2] bc 85 [2] ba b0 [2] 94 b0 [2] ab ac }

  condition:
    any of them
}