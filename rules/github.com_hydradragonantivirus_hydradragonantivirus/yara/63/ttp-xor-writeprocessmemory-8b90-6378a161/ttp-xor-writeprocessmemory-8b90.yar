rule TTP_XOR_WriteProcessMemory_8b90 {
  strings:
    $key_8b90 = { dc e2 [2] ee c0 [2] e8 f5 [2] c6 f5 [2] f9 e9 }

  condition:
    any of them
}