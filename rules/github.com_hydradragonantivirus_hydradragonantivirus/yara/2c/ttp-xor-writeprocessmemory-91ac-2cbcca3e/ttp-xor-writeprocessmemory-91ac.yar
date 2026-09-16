rule TTP_XOR_WriteProcessMemory_91ac {
  strings:
    $key_91ac = { c6 de [2] f4 fc [2] f2 c9 [2] dc c9 [2] e3 d5 }

  condition:
    any of them
}