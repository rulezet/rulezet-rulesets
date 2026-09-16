rule TTP_XOR_WriteProcessMemory_f1c1 {
  strings:
    $key_f1c1 = { a6 b3 [2] 94 91 [2] 92 a4 [2] bc a4 [2] 83 b8 }

  condition:
    any of them
}