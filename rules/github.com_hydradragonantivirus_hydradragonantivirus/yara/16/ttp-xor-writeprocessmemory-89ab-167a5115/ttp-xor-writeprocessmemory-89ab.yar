rule TTP_XOR_WriteProcessMemory_89ab {
  strings:
    $key_89ab = { de d9 [2] ec fb [2] ea ce [2] c4 ce [2] fb d2 }

  condition:
    any of them
}