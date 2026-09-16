rule TTP_XOR_WriteProcessMemory_8b1b {
  strings:
    $key_8b1b = { dc 69 [2] ee 4b [2] e8 7e [2] c6 7e [2] f9 62 }

  condition:
    any of them
}