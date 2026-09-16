rule TTP_XOR_WriteProcessMemory_8b69 {
  strings:
    $key_8b69 = { dc 1b [2] ee 39 [2] e8 0c [2] c6 0c [2] f9 10 }

  condition:
    any of them
}