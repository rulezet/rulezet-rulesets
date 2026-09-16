rule TTP_XOR_WriteProcessMemory_8b39 {
  strings:
    $key_8b39 = { dc 4b [2] ee 69 [2] e8 5c [2] c6 5c [2] f9 40 }

  condition:
    any of them
}