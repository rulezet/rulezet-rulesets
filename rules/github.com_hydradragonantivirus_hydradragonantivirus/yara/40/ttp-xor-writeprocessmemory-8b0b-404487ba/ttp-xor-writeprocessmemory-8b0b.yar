rule TTP_XOR_WriteProcessMemory_8b0b {
  strings:
    $key_8b0b = { dc 79 [2] ee 5b [2] e8 6e [2] c6 6e [2] f9 72 }

  condition:
    any of them
}