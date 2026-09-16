rule TTP_XOR_WriteProcessMemory_dfd6 {
  strings:
    $key_dfd6 = { 88 a4 [2] ba 86 [2] bc b3 [2] 92 b3 [2] ad af }

  condition:
    any of them
}