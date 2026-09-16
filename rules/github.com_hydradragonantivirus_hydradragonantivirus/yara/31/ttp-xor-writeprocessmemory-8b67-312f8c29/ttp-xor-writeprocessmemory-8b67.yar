rule TTP_XOR_WriteProcessMemory_8b67 {
  strings:
    $key_8b67 = { dc 15 [2] ee 37 [2] e8 02 [2] c6 02 [2] f9 1e }

  condition:
    any of them
}