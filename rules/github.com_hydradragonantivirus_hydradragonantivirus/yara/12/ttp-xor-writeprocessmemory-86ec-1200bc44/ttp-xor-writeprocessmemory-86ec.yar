rule TTP_XOR_WriteProcessMemory_86ec {
  strings:
    $key_86ec = { d1 9e [2] e3 bc [2] e5 89 [2] cb 89 [2] f4 95 }

  condition:
    any of them
}