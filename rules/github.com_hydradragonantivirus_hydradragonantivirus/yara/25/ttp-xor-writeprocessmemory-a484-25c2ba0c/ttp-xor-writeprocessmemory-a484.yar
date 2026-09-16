rule TTP_XOR_WriteProcessMemory_a484 {
  strings:
    $key_a484 = { f3 f6 [2] c1 d4 [2] c7 e1 [2] e9 e1 [2] d6 fd }

  condition:
    any of them
}