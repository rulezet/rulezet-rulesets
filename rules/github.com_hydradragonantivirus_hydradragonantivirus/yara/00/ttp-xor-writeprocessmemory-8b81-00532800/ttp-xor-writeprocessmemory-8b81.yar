rule TTP_XOR_WriteProcessMemory_8b81 {
  strings:
    $key_8b81 = { dc f3 [2] ee d1 [2] e8 e4 [2] c6 e4 [2] f9 f8 }

  condition:
    any of them
}