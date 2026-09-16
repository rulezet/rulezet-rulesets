rule TTP_XOR_WriteProcessMemory_a2d1 {
  strings:
    $key_a2d1 = { f5 a3 [2] c7 81 [2] c1 b4 [2] ef b4 [2] d0 a8 }

  condition:
    any of them
}