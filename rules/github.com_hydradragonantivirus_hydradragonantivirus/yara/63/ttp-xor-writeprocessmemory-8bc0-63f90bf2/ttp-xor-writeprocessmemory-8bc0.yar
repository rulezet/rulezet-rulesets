rule TTP_XOR_WriteProcessMemory_8bc0 {
  strings:
    $key_8bc0 = { dc b2 [2] ee 90 [2] e8 a5 [2] c6 a5 [2] f9 b9 }

  condition:
    any of them
}