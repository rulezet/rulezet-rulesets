rule TTP_XOR_WriteProcessMemory_8b15 {
  strings:
    $key_8b15 = { dc 67 [2] ee 45 [2] e8 70 [2] c6 70 [2] f9 6c }

  condition:
    any of them
}