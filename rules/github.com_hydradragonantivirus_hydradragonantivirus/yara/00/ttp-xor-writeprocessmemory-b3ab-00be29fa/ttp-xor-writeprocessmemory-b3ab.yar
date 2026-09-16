rule TTP_XOR_WriteProcessMemory_b3ab {
  strings:
    $key_b3ab = { e4 d9 [2] d6 fb [2] d0 ce [2] fe ce [2] c1 d2 }

  condition:
    any of them
}