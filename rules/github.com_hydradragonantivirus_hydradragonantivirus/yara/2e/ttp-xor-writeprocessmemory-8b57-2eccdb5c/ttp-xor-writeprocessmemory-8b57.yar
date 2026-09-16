rule TTP_XOR_WriteProcessMemory_8b57 {
  strings:
    $key_8b57 = { dc 25 [2] ee 07 [2] e8 32 [2] c6 32 [2] f9 2e }

  condition:
    any of them
}