rule TTP_XOR_WriteProcessMemory_8b25 {
  strings:
    $key_8b25 = { dc 57 [2] ee 75 [2] e8 40 [2] c6 40 [2] f9 5c }

  condition:
    any of them
}