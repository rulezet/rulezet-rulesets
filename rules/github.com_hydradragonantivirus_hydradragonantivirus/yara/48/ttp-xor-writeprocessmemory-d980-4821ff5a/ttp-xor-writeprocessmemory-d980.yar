rule TTP_XOR_WriteProcessMemory_d980 {
  strings:
    $key_d980 = { 8e f2 [2] bc d0 [2] ba e5 [2] 94 e5 [2] ab f9 }

  condition:
    any of them
}