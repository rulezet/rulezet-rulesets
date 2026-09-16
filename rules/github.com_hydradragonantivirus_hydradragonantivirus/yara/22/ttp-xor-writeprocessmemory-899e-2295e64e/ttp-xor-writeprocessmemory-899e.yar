rule TTP_XOR_WriteProcessMemory_899e {
  strings:
    $key_899e = { de ec [2] ec ce [2] ea fb [2] c4 fb [2] fb e7 }

  condition:
    any of them
}