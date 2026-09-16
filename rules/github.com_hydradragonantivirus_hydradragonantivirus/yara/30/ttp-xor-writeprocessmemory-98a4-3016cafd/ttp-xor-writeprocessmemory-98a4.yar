rule TTP_XOR_WriteProcessMemory_98a4 {
  strings:
    $key_98a4 = { cf d6 [2] fd f4 [2] fb c1 [2] d5 c1 [2] ea dd }

  condition:
    any of them
}