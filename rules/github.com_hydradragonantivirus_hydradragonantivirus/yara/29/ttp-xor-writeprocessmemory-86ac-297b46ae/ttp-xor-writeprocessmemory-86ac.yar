rule TTP_XOR_WriteProcessMemory_86ac {
  strings:
    $key_86ac = { d1 de [2] e3 fc [2] e5 c9 [2] cb c9 [2] f4 d5 }

  condition:
    any of them
}