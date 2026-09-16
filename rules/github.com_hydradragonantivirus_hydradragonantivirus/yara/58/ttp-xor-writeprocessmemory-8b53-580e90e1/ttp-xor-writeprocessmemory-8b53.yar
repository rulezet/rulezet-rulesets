rule TTP_XOR_WriteProcessMemory_8b53 {
  strings:
    $key_8b53 = { dc 21 [2] ee 03 [2] e8 36 [2] c6 36 [2] f9 2a }

  condition:
    any of them
}