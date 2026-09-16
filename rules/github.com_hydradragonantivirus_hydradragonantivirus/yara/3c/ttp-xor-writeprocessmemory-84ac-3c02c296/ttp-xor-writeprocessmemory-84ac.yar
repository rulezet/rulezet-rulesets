rule TTP_XOR_WriteProcessMemory_84ac {
  strings:
    $key_84ac = { d3 de [2] e1 fc [2] e7 c9 [2] c9 c9 [2] f6 d5 }

  condition:
    any of them
}