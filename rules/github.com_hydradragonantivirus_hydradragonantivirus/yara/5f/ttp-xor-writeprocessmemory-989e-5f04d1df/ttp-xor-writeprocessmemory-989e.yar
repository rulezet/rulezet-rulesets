rule TTP_XOR_WriteProcessMemory_989e {
  strings:
    $key_989e = { cf ec [2] fd ce [2] fb fb [2] d5 fb [2] ea e7 }

  condition:
    any of them
}