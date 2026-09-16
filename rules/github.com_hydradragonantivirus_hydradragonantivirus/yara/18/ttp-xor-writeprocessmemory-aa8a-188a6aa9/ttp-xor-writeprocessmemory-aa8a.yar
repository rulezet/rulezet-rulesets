rule TTP_XOR_WriteProcessMemory_aa8a {
  strings:
    $key_aa8a = { fd f8 [2] cf da [2] c9 ef [2] e7 ef [2] d8 f3 }

  condition:
    any of them
}