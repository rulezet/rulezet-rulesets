rule TTP_XOR_WriteProcessMemory_8b07 {
  strings:
    $key_8b07 = { dc 75 [2] ee 57 [2] e8 62 [2] c6 62 [2] f9 7e }

  condition:
    any of them
}