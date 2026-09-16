rule TTP_XOR_WriteProcessMemory_8b33 {
  strings:
    $key_8b33 = { dc 41 [2] ee 63 [2] e8 56 [2] c6 56 [2] f9 4a }

  condition:
    any of them
}