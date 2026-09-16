rule TTP_XOR_WriteProcessMemory_a895 {
  strings:
    $key_a895 = { ff e7 [2] cd c5 [2] cb f0 [2] e5 f0 [2] da ec }

  condition:
    any of them
}