rule TTP_XOR_WriteProcessMemory_8bd0 {
  strings:
    $key_8bd0 = { dc a2 [2] ee 80 [2] e8 b5 [2] c6 b5 [2] f9 a9 }

  condition:
    any of them
}