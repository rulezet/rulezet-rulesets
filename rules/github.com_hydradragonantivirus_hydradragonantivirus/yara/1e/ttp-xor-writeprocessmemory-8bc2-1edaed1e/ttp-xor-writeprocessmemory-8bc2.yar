rule TTP_XOR_WriteProcessMemory_8bc2 {
  strings:
    $key_8bc2 = { dc b0 [2] ee 92 [2] e8 a7 [2] c6 a7 [2] f9 bb }

  condition:
    any of them
}