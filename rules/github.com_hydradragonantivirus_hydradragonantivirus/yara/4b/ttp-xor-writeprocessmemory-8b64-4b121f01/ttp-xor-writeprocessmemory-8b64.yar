rule TTP_XOR_WriteProcessMemory_8b64 {
  strings:
    $key_8b64 = { dc 16 [2] ee 34 [2] e8 01 [2] c6 01 [2] f9 1d }

  condition:
    any of them
}