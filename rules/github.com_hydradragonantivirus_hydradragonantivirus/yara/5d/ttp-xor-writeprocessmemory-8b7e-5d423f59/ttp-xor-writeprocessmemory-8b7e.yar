rule TTP_XOR_WriteProcessMemory_8b7e {
  strings:
    $key_8b7e = { dc 0c [2] ee 2e [2] e8 1b [2] c6 1b [2] f9 07 }

  condition:
    any of them
}