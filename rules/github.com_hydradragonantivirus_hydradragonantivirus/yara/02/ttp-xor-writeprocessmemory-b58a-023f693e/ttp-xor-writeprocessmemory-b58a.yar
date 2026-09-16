rule TTP_XOR_WriteProcessMemory_b58a {
  strings:
    $key_b58a = { e2 f8 [2] d0 da [2] d6 ef [2] f8 ef [2] c7 f3 }

  condition:
    any of them
}