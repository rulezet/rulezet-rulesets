rule TTP_XOR_WriteProcessMemory_98b0 {
  strings:
    $key_98b0 = { cf c2 [2] fd e0 [2] fb d5 [2] d5 d5 [2] ea c9 }

  condition:
    any of them
}