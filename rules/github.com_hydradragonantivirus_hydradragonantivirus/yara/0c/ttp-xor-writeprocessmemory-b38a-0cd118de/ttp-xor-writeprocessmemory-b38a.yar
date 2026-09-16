rule TTP_XOR_WriteProcessMemory_b38a {
  strings:
    $key_b38a = { e4 f8 [2] d6 da [2] d0 ef [2] fe ef [2] c1 f3 }

  condition:
    any of them
}