rule TTP_XOR_WriteProcessMemory_a2c6 {
  strings:
    $key_a2c6 = { f5 b4 [2] c7 96 [2] c1 a3 [2] ef a3 [2] d0 bf }

  condition:
    any of them
}