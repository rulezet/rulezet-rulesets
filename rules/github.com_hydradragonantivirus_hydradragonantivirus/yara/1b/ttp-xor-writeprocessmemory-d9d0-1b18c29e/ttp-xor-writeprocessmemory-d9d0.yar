rule TTP_XOR_WriteProcessMemory_d9d0 {
  strings:
    $key_d9d0 = { 8e a2 [2] bc 80 [2] ba b5 [2] 94 b5 [2] ab a9 }

  condition:
    any of them
}