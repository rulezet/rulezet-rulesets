rule TTP_XOR_WriteProcessMemory_8b04 {
  strings:
    $key_8b04 = { dc 76 [2] ee 54 [2] e8 61 [2] c6 61 [2] f9 7d }

  condition:
    any of them
}