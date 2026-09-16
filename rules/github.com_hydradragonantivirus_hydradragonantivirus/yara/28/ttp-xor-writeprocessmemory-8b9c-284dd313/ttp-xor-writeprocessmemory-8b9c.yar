rule TTP_XOR_WriteProcessMemory_8b9c {
  strings:
    $key_8b9c = { dc ee [2] ee cc [2] e8 f9 [2] c6 f9 [2] f9 e5 }

  condition:
    any of them
}