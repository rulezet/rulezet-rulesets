rule TTP_XOR_WriteProcessMemory_a7c3 {
  strings:
    $key_a7c3 = { f0 b1 [2] c2 93 [2] c4 a6 [2] ea a6 [2] d5 ba }

  condition:
    any of them
}