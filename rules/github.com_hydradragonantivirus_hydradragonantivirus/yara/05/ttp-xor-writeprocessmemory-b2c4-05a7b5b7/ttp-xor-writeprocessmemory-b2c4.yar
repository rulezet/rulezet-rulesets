rule TTP_XOR_WriteProcessMemory_b2c4 {
  strings:
    $key_b2c4 = { e5 b6 [2] d7 94 [2] d1 a1 [2] ff a1 [2] c0 bd }

  condition:
    any of them
}