rule TTP_XOR_WriteProcessMemory_e58a {
  strings:
    $key_e58a = { b2 f8 [2] 80 da [2] 86 ef [2] a8 ef [2] 97 f3 }

  condition:
    any of them
}