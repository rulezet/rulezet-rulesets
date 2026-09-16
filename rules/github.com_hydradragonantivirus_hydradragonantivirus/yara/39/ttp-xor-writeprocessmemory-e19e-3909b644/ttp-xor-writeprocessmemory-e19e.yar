rule TTP_XOR_WriteProcessMemory_e19e {
  strings:
    $key_e19e = { b6 ec [2] 84 ce [2] 82 fb [2] ac fb [2] 93 e7 }

  condition:
    any of them
}