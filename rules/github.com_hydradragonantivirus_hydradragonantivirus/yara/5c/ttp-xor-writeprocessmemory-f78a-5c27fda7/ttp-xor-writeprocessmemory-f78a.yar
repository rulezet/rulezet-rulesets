rule TTP_XOR_WriteProcessMemory_f78a {
  strings:
    $key_f78a = { a0 f8 [2] 92 da [2] 94 ef [2] ba ef [2] 85 f3 }

  condition:
    any of them
}