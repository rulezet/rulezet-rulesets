rule TTP_XOR_WriteProcessMemory_8d8a {
  strings:
    $key_8d8a = { da f8 [2] e8 da [2] ee ef [2] c0 ef [2] ff f3 }

  condition:
    any of them
}