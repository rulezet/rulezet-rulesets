rule TTP_XOR_WriteProcessMemory_8b84 {
  strings:
    $key_8b84 = { dc f6 [2] ee d4 [2] e8 e1 [2] c6 e1 [2] f9 fd }

  condition:
    any of them
}