rule TTP_XOR_WriteProcessMemory_8b36 {
  strings:
    $key_8b36 = { dc 44 [2] ee 66 [2] e8 53 [2] c6 53 [2] f9 4f }

  condition:
    any of them
}