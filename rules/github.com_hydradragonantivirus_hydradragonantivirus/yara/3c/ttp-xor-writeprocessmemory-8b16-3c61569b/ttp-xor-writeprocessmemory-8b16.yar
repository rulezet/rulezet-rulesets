rule TTP_XOR_WriteProcessMemory_8b16 {
  strings:
    $key_8b16 = { dc 64 [2] ee 46 [2] e8 73 [2] c6 73 [2] f9 6f }

  condition:
    any of them
}