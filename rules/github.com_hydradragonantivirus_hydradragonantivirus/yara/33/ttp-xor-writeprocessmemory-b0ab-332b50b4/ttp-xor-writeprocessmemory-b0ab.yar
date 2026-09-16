rule TTP_XOR_WriteProcessMemory_b0ab {
  strings:
    $key_b0ab = { e7 d9 [2] d5 fb [2] d3 ce [2] fd ce [2] c2 d2 }

  condition:
    any of them
}