rule TTP_XOR_WriteProcessMemory_98bc {
  strings:
    $key_98bc = { cf ce [2] fd ec [2] fb d9 [2] d5 d9 [2] ea c5 }

  condition:
    any of them
}