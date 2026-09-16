rule TTP_XOR_WriteProcessMemory_a58a {
  strings:
    $key_a58a = { f2 f8 [2] c0 da [2] c6 ef [2] e8 ef [2] d7 f3 }

  condition:
    any of them
}