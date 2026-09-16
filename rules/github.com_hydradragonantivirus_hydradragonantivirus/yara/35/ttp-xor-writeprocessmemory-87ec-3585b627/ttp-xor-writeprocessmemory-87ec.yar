rule TTP_XOR_WriteProcessMemory_87ec {
  strings:
    $key_87ec = { d0 9e [2] e2 bc [2] e4 89 [2] ca 89 [2] f5 95 }

  condition:
    any of them
}