rule TTP_XOR_WriteProcessMemory_a2c0 {
  strings:
    $key_a2c0 = { f5 b2 [2] c7 90 [2] c1 a5 [2] ef a5 [2] d0 b9 }

  condition:
    any of them
}