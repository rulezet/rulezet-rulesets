rule TTP_XOR_WriteProcessMemory_a2d5 {
  strings:
    $key_a2d5 = { f5 a7 [2] c7 85 [2] c1 b0 [2] ef b0 [2] d0 ac }

  condition:
    any of them
}