rule TTP_XOR_WriteProcessMemory_8b4d {
  strings:
    $key_8b4d = { dc 3f [2] ee 1d [2] e8 28 [2] c6 28 [2] f9 34 }

  condition:
    any of them
}