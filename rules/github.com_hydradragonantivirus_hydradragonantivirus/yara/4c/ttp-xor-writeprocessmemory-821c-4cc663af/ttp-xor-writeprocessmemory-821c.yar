rule TTP_XOR_WriteProcessMemory_821c {
  strings:
    $key_821c = { d5 6e [2] e7 4c [2] e1 79 [2] cf 79 [2] f0 65 }

  condition:
    any of them
}