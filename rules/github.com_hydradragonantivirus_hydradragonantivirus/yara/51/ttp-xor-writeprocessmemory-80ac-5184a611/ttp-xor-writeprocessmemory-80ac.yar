rule TTP_XOR_WriteProcessMemory_80ac {
  strings:
    $key_80ac = { d7 de [2] e5 fc [2] e3 c9 [2] cd c9 [2] f2 d5 }

  condition:
    any of them
}