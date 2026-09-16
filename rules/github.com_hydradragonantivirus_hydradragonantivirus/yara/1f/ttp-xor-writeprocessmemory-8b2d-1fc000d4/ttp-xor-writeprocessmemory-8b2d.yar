rule TTP_XOR_WriteProcessMemory_8b2d {
  strings:
    $key_8b2d = { dc 5f [2] ee 7d [2] e8 48 [2] c6 48 [2] f9 54 }

  condition:
    any of them
}