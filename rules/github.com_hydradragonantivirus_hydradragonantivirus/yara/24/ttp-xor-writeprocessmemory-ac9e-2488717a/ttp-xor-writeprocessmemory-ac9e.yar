rule TTP_XOR_WriteProcessMemory_ac9e {
  strings:
    $key_ac9e = { fb ec [2] c9 ce [2] cf fb [2] e1 fb [2] de e7 }

  condition:
    any of them
}