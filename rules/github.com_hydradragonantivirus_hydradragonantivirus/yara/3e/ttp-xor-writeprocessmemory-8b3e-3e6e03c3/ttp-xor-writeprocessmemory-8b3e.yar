rule TTP_XOR_WriteProcessMemory_8b3e {
  strings:
    $key_8b3e = { dc 4c [2] ee 6e [2] e8 5b [2] c6 5b [2] f9 47 }

  condition:
    any of them
}