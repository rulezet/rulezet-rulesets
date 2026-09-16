rule TTP_XOR_WriteProcessMemory_8b65 {
  strings:
    $key_8b65 = { dc 17 [2] ee 35 [2] e8 00 [2] c6 00 [2] f9 1c }

  condition:
    any of them
}