rule TTP_XOR_WriteProcessMemory_8b35 {
  strings:
    $key_8b35 = { dc 47 [2] ee 65 [2] e8 50 [2] c6 50 [2] f9 4c }

  condition:
    any of them
}