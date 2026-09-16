rule TTP_XOR_WriteProcessMemory_8b43 {
  strings:
    $key_8b43 = { dc 31 [2] ee 13 [2] e8 26 [2] c6 26 [2] f9 3a }

  condition:
    any of them
}