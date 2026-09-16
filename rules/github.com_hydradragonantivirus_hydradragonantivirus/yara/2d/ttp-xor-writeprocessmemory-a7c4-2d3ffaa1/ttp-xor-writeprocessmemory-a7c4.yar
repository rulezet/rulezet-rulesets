rule TTP_XOR_WriteProcessMemory_a7c4 {
  strings:
    $key_a7c4 = { f0 b6 [2] c2 94 [2] c4 a1 [2] ea a1 [2] d5 bd }

  condition:
    any of them
}