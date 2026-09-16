rule TTP_XOR_WriteProcessMemory_8bbc {
  strings:
    $key_8bbc = { dc ce [2] ee ec [2] e8 d9 [2] c6 d9 [2] f9 c5 }

  condition:
    any of them
}