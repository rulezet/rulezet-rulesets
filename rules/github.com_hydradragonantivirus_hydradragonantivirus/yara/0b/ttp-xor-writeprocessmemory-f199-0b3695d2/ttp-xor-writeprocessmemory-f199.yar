rule TTP_XOR_WriteProcessMemory_f199 {
  strings:
    $key_f199 = { a6 eb [2] 94 c9 [2] 92 fc [2] bc fc [2] 83 e0 }

  condition:
    any of them
}