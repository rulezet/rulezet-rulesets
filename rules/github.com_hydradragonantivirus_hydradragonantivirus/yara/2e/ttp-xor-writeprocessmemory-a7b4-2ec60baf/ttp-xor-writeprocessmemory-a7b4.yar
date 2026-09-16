rule TTP_XOR_WriteProcessMemory_a7b4 {
  strings:
    $key_a7b4 = { f0 c6 [2] c2 e4 [2] c4 d1 [2] ea d1 [2] d5 cd }

  condition:
    any of them
}