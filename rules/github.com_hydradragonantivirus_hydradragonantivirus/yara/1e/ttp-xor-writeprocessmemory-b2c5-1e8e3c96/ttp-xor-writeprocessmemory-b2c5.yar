rule TTP_XOR_WriteProcessMemory_b2c5 {
  strings:
    $key_b2c5 = { e5 b7 [2] d7 95 [2] d1 a0 [2] ff a0 [2] c0 bc }

  condition:
    any of them
}