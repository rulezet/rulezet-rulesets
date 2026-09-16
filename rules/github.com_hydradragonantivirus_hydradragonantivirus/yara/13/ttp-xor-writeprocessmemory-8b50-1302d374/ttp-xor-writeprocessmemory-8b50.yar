rule TTP_XOR_WriteProcessMemory_8b50 {
  strings:
    $key_8b50 = { dc 22 [2] ee 00 [2] e8 35 [2] c6 35 [2] f9 29 }

  condition:
    any of them
}