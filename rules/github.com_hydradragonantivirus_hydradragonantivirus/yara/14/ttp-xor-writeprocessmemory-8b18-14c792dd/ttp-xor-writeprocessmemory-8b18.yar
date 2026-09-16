rule TTP_XOR_WriteProcessMemory_8b18 {
  strings:
    $key_8b18 = { dc 6a [2] ee 48 [2] e8 7d [2] c6 7d [2] f9 61 }

  condition:
    any of them
}