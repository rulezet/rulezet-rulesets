rule TTP_XOR_WriteProcessMemory_ba9e {
  strings:
    $key_ba9e = { ed ec [2] df ce [2] d9 fb [2] f7 fb [2] c8 e7 }

  condition:
    any of them
}