rule TTP_XOR_WriteProcessMemory_8b05 {
  strings:
    $key_8b05 = { dc 77 [2] ee 55 [2] e8 60 [2] c6 60 [2] f9 7c }

  condition:
    any of them
}