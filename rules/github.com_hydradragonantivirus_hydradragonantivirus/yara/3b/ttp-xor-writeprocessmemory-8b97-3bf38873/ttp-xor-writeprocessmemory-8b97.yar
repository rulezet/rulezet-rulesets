rule TTP_XOR_WriteProcessMemory_8b97 {
  strings:
    $key_8b97 = { dc e5 [2] ee c7 [2] e8 f2 [2] c6 f2 [2] f9 ee }

  condition:
    any of them
}