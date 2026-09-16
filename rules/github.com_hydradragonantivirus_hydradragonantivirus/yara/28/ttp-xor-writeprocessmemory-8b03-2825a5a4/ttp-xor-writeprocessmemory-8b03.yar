rule TTP_XOR_WriteProcessMemory_8b03 {
  strings:
    $key_8b03 = { dc 71 [2] ee 53 [2] e8 66 [2] c6 66 [2] f9 7a }

  condition:
    any of them
}