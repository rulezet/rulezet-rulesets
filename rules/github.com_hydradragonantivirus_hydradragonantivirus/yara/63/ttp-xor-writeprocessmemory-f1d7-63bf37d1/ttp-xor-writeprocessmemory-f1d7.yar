rule TTP_XOR_WriteProcessMemory_f1d7 {
  strings:
    $key_f1d7 = { a6 a5 [2] 94 87 [2] 92 b2 [2] bc b2 [2] 83 ae }

  condition:
    any of them
}