rule TTP_XOR_WriteProcessMemory_92ec {
  strings:
    $key_92ec = { c5 9e [2] f7 bc [2] f1 89 [2] df 89 [2] e0 95 }

  condition:
    any of them
}