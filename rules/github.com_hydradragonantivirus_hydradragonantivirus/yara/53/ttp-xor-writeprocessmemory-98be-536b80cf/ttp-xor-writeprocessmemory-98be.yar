rule TTP_XOR_WriteProcessMemory_98be {
  strings:
    $key_98be = { cf cc [2] fd ee [2] fb db [2] d5 db [2] ea c7 }

  condition:
    any of them
}