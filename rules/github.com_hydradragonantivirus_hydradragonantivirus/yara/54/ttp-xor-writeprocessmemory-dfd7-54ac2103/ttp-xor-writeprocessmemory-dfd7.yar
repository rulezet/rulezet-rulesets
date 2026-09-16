rule TTP_XOR_WriteProcessMemory_dfd7 {
  strings:
    $key_dfd7 = { 88 a5 [2] ba 87 [2] bc b2 [2] 92 b2 [2] ad ae }

  condition:
    any of them
}