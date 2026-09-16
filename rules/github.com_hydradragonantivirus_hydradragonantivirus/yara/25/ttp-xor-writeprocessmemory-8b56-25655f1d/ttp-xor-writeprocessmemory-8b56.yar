rule TTP_XOR_WriteProcessMemory_8b56 {
  strings:
    $key_8b56 = { dc 24 [2] ee 06 [2] e8 33 [2] c6 33 [2] f9 2f }

  condition:
    any of them
}