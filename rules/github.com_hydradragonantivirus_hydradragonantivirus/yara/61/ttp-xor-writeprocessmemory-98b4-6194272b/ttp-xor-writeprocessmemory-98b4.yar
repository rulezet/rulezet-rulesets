rule TTP_XOR_WriteProcessMemory_98b4 {
  strings:
    $key_98b4 = { cf c6 [2] fd e4 [2] fb d1 [2] d5 d1 [2] ea cd }

  condition:
    any of them
}