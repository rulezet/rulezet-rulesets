rule TTP_XOR_WriteProcessMemory_a7c1 {
  strings:
    $key_a7c1 = { f0 b3 [2] c2 91 [2] c4 a4 [2] ea a4 [2] d5 b8 }

  condition:
    any of them
}