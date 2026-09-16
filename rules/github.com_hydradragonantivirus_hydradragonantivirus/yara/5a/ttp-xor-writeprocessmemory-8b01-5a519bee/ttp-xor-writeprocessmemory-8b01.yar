rule TTP_XOR_WriteProcessMemory_8b01 {
  strings:
    $key_8b01 = { dc 73 [2] ee 51 [2] e8 64 [2] c6 64 [2] f9 78 }

  condition:
    any of them
}