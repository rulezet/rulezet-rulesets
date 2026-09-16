rule TTP_XOR_WriteProcessMemory_8b2c {
  strings:
    $key_8b2c = { dc 5e [2] ee 7c [2] e8 49 [2] c6 49 [2] f9 55 }

  condition:
    any of them
}