rule TTP_XOR_WriteProcessMemory_b78a {
  strings:
    $key_b78a = { e0 f8 [2] d2 da [2] d4 ef [2] fa ef [2] c5 f3 }

  condition:
    any of them
}