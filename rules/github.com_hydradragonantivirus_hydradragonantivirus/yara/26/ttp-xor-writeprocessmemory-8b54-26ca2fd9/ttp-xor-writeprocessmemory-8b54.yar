rule TTP_XOR_WriteProcessMemory_8b54 {
  strings:
    $key_8b54 = { dc 26 [2] ee 04 [2] e8 31 [2] c6 31 [2] f9 2d }

  condition:
    any of them
}