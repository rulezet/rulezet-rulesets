rule TTP_XOR_WriteProcessMemory_8b55 {
  strings:
    $key_8b55 = { dc 27 [2] ee 05 [2] e8 30 [2] c6 30 [2] f9 2c }

  condition:
    any of them
}