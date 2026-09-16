rule TTP_XOR_WriteProcessMemory_f1dc {
  strings:
    $key_f1dc = { a6 ae [2] 94 8c [2] 92 b9 [2] bc b9 [2] 83 a5 }

  condition:
    any of them
}