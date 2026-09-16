rule TTP_XOR_WriteProcessMemory_8b9b {
  strings:
    $key_8b9b = { dc e9 [2] ee cb [2] e8 fe [2] c6 fe [2] f9 e2 }

  condition:
    any of them
}