rule TTP_XOR_WriteProcessMemory_98a7 {
  strings:
    $key_98a7 = { cf d5 [2] fd f7 [2] fb c2 [2] d5 c2 [2] ea de }

  condition:
    any of them
}