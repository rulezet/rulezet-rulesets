rule TTP_XOR_WriteProcessMemory_a2c7 {
  strings:
    $key_a2c7 = { f5 b5 [2] c7 97 [2] c1 a2 [2] ef a2 [2] d0 be }

  condition:
    any of them
}