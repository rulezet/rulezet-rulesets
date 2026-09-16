rule TTP_XOR_WriteProcessMemory_8b21 {
  strings:
    $key_8b21 = { dc 53 [2] ee 71 [2] e8 44 [2] c6 44 [2] f9 58 }

  condition:
    any of them
}