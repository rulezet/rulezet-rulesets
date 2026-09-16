rule TTP_XOR_WriteProcessMemory_80ec {
  strings:
    $key_80ec = { d7 9e [2] e5 bc [2] e3 89 [2] cd 89 [2] f2 95 }

  condition:
    any of them
}