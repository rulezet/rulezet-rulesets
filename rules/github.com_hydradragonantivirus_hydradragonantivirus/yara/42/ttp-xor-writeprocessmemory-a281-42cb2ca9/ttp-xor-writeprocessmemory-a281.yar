rule TTP_XOR_WriteProcessMemory_a281 {
  strings:
    $key_a281 = { f5 f3 [2] c7 d1 [2] c1 e4 [2] ef e4 [2] d0 f8 }

  condition:
    any of them
}