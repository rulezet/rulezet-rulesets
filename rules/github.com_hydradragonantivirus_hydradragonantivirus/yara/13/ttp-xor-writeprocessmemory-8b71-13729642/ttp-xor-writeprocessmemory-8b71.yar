rule TTP_XOR_WriteProcessMemory_8b71 {
  strings:
    $key_8b71 = { dc 03 [2] ee 21 [2] e8 14 [2] c6 14 [2] f9 08 }

  condition:
    any of them
}