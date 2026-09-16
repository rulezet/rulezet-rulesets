rule TTP_XOR_WriteProcessMemory_a28a {
  strings:
    $key_a28a = { f5 f8 [2] c7 da [2] c1 ef [2] ef ef [2] d0 f3 }

  condition:
    any of them
}