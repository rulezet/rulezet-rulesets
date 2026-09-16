rule TTP_XOR_WriteProcessMemory_b6ab {
  strings:
    $key_b6ab = { e1 d9 [2] d3 fb [2] d5 ce [2] fb ce [2] c4 d2 }

  condition:
    any of them
}