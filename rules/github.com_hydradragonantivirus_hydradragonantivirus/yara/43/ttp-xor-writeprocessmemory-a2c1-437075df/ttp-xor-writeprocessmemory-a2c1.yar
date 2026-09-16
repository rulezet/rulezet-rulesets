rule TTP_XOR_WriteProcessMemory_a2c1 {
  strings:
    $key_a2c1 = { f5 b3 [2] c7 91 [2] c1 a4 [2] ef a4 [2] d0 b8 }

  condition:
    any of them
}