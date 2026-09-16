rule TTP_XOR_WriteProcessMemory_f19d {
  strings:
    $key_f19d = { a6 ef [2] 94 cd [2] 92 f8 [2] bc f8 [2] 83 e4 }

  condition:
    any of them
}