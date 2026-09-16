rule TTP_XOR_WriteProcessMemory_8b74 {
  strings:
    $key_8b74 = { dc 06 [2] ee 24 [2] e8 11 [2] c6 11 [2] f9 0d }

  condition:
    any of them
}