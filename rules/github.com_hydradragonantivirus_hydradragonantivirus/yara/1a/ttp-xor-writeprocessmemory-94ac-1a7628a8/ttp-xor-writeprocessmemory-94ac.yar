rule TTP_XOR_WriteProcessMemory_94ac {
  strings:
    $key_94ac = { c3 de [2] f1 fc [2] f7 c9 [2] d9 c9 [2] e6 d5 }

  condition:
    any of them
}