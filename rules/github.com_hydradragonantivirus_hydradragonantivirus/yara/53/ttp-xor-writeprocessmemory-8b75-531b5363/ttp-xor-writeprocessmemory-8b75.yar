rule TTP_XOR_WriteProcessMemory_8b75 {
  strings:
    $key_8b75 = { dc 07 [2] ee 25 [2] e8 10 [2] c6 10 [2] f9 0c }

  condition:
    any of them
}