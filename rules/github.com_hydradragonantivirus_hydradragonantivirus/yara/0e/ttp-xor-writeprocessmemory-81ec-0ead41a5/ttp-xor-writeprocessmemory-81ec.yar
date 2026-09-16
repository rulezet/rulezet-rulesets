rule TTP_XOR_WriteProcessMemory_81ec {
  strings:
    $key_81ec = { d6 9e [2] e4 bc [2] e2 89 [2] cc 89 [2] f3 95 }

  condition:
    any of them
}