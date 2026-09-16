rule TTP_XOR_WriteProcessMemory_8bcd {
  strings:
    $key_8bcd = { dc bf [2] ee 9d [2] e8 a8 [2] c6 a8 [2] f9 b4 }

  condition:
    any of them
}