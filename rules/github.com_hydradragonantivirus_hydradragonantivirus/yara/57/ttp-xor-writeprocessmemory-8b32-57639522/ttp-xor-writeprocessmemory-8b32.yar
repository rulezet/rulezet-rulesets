rule TTP_XOR_WriteProcessMemory_8b32 {
  strings:
    $key_8b32 = { dc 40 [2] ee 62 [2] e8 57 [2] c6 57 [2] f9 4b }

  condition:
    any of them
}