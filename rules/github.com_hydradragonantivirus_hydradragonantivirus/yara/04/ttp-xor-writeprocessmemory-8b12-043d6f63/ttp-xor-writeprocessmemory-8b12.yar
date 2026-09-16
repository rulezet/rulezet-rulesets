rule TTP_XOR_WriteProcessMemory_8b12 {
  strings:
    $key_8b12 = { dc 60 [2] ee 42 [2] e8 77 [2] c6 77 [2] f9 6b }

  condition:
    any of them
}