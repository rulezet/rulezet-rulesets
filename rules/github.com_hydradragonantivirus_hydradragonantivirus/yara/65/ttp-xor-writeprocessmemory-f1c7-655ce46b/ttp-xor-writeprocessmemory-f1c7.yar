rule TTP_XOR_WriteProcessMemory_f1c7 {
  strings:
    $key_f1c7 = { a6 b5 [2] 94 97 [2] 92 a2 [2] bc a2 [2] 83 be }

  condition:
    any of them
}