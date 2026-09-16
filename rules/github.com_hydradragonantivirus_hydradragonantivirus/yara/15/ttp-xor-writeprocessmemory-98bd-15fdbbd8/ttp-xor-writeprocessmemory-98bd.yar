rule TTP_XOR_WriteProcessMemory_98bd {
  strings:
    $key_98bd = { cf cf [2] fd ed [2] fb d8 [2] d5 d8 [2] ea c4 }

  condition:
    any of them
}