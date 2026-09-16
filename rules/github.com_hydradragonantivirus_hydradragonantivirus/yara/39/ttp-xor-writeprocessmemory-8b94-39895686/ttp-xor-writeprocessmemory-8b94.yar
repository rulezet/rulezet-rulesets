rule TTP_XOR_WriteProcessMemory_8b94 {
  strings:
    $key_8b94 = { dc e6 [2] ee c4 [2] e8 f1 [2] c6 f1 [2] f9 ed }

  condition:
    any of them
}