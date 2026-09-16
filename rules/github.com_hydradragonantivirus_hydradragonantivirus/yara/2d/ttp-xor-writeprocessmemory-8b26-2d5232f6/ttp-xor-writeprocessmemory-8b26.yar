rule TTP_XOR_WriteProcessMemory_8b26 {
  strings:
    $key_8b26 = { dc 54 [2] ee 76 [2] e8 43 [2] c6 43 [2] f9 5f }

  condition:
    any of them
}