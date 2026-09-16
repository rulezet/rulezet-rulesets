rule TTP_XOR_WriteProcessMemory_a256 {
  strings:
    $key_a256 = { f5 24 [2] c7 06 [2] c1 33 [2] ef 33 [2] d0 2f }

  condition:
    any of them
}