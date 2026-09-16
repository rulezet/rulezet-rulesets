rule TTP_XOR_WriteProcessMemory_857b {
  strings:
    $key_857b = { d2 09 [2] e0 2b [2] e6 1e [2] c8 1e [2] f7 02 }

  condition:
    any of them
}