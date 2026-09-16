rule TTP_XOR_WriteProcessMemory_8b78 {
  strings:
    $key_8b78 = { dc 0a [2] ee 28 [2] e8 1d [2] c6 1d [2] f9 01 }

  condition:
    any of them
}