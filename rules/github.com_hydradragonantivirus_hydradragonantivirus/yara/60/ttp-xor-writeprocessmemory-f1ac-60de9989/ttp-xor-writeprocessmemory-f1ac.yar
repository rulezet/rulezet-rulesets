rule TTP_XOR_WriteProcessMemory_f1ac {
  strings:
    $key_f1ac = { a6 de [2] 94 fc [2] 92 c9 [2] bc c9 [2] 83 d5 }

  condition:
    any of them
}