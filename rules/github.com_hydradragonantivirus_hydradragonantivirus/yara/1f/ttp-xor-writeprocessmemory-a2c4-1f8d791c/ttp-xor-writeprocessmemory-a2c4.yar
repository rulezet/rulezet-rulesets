rule TTP_XOR_WriteProcessMemory_a2c4 {
  strings:
    $key_a2c4 = { f5 b6 [2] c7 94 [2] c1 a1 [2] ef a1 [2] d0 bd }

  condition:
    any of them
}