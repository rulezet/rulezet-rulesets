rule TTP_XOR_WriteProcessMemory_a2d2 {
  strings:
    $key_a2d2 = { f5 a0 [2] c7 82 [2] c1 b7 [2] ef b7 [2] d0 ab }

  condition:
    any of them
}