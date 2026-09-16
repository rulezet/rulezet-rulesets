rule TTP_XOR_WriteProcessMemory_8b5e {
  strings:
    $key_8b5e = { dc 2c [2] ee 0e [2] e8 3b [2] c6 3b [2] f9 27 }

  condition:
    any of them
}