rule TTP_XOR_WriteProcessMemory_8b44 {
  strings:
    $key_8b44 = { dc 36 [2] ee 14 [2] e8 21 [2] c6 21 [2] f9 3d }

  condition:
    any of them
}