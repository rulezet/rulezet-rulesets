rule TTP_XOR_WriteProcessMemory_8b1e {
  strings:
    $key_8b1e = { dc 6c [2] ee 4e [2] e8 7b [2] c6 7b [2] f9 67 }

  condition:
    any of them
}