rule TTP_XOR_WriteProcessMemory_d98a {
  strings:
    $key_d98a = { 8e f8 [2] bc da [2] ba ef [2] 94 ef [2] ab f3 }

  condition:
    any of them
}