rule TTP_XOR_WriteProcessMemory_8b47 {
  strings:
    $key_8b47 = { dc 35 [2] ee 17 [2] e8 22 [2] c6 22 [2] f9 3e }

  condition:
    any of them
}