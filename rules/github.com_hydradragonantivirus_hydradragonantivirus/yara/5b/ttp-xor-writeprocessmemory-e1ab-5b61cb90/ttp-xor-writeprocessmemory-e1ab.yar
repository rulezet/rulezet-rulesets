rule TTP_XOR_WriteProcessMemory_e1ab {
  strings:
    $key_e1ab = { b6 d9 [2] 84 fb [2] 82 ce [2] ac ce [2] 93 d2 }

  condition:
    any of them
}