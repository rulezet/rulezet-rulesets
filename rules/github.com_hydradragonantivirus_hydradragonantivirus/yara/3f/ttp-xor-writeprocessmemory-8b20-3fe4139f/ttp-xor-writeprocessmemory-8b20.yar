rule TTP_XOR_WriteProcessMemory_8b20 {
  strings:
    $key_8b20 = { dc 52 [2] ee 70 [2] e8 45 [2] c6 45 [2] f9 59 }

  condition:
    any of them
}