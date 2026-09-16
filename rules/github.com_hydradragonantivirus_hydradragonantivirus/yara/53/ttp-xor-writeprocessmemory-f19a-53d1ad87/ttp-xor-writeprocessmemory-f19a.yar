rule TTP_XOR_WriteProcessMemory_f19a {
  strings:
    $key_f19a = { a6 e8 [2] 94 ca [2] 92 ff [2] bc ff [2] 83 e3 }

  condition:
    any of them
}