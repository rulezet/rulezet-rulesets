rule TTP_XOR_WriteProcessMemory_98a0 {
  strings:
    $key_98a0 = { cf d2 [2] fd f0 [2] fb c5 [2] d5 c5 [2] ea d9 }

  condition:
    any of them
}