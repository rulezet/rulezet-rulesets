rule TTP_XOR_WriteProcessMemory_98bf {
  strings:
    $key_98bf = { cf cd [2] fd ef [2] fb da [2] d5 da [2] ea c6 }

  condition:
    any of them
}