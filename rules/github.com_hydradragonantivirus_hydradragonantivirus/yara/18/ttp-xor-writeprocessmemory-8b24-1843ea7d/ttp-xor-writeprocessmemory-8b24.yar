rule TTP_XOR_WriteProcessMemory_8b24 {
  strings:
    $key_8b24 = { dc 56 [2] ee 74 [2] e8 41 [2] c6 41 [2] f9 5d }

  condition:
    any of them
}