rule TTP_XOR_WriteProcessMemory_8c8a {
  strings:
    $key_8c8a = { db f8 [2] e9 da [2] ef ef [2] c1 ef [2] fe f3 }

  condition:
    any of them
}