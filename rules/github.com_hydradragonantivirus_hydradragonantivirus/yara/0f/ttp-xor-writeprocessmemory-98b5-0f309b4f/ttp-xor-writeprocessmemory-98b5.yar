rule TTP_XOR_WriteProcessMemory_98b5 {
  strings:
    $key_98b5 = { cf c7 [2] fd e5 [2] fb d0 [2] d5 d0 [2] ea cc }

  condition:
    any of them
}