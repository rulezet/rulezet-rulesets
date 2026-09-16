rule TTP_XOR_WriteProcessMemory_a2d7 {
  strings:
    $key_a2d7 = { f5 a5 [2] c7 87 [2] c1 b2 [2] ef b2 [2] d0 ae }

  condition:
    any of them
}