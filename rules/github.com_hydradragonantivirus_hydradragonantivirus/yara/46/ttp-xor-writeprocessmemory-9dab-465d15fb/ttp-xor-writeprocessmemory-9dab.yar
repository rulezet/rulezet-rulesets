rule TTP_XOR_WriteProcessMemory_9dab {
  strings:
    $key_9dab = { ca d9 [2] f8 fb [2] fe ce [2] d0 ce [2] ef d2 }

  condition:
    any of them
}