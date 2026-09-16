rule TTP_XOR_WriteProcessMemory_8b52 {
  strings:
    $key_8b52 = { dc 20 [2] ee 02 [2] e8 37 [2] c6 37 [2] f9 2b }

  condition:
    any of them
}