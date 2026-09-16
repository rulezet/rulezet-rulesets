rule TTP_XOR_WriteProcessMemory_f1dd {
  strings:
    $key_f1dd = { a6 af [2] 94 8d [2] 92 b8 [2] bc b8 [2] 83 a4 }

  condition:
    any of them
}