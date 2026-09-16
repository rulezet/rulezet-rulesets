rule TTP_XOR_WriteProcessMemory_a320 {
  strings:
    $key_a320 = { f4 52 [2] c6 70 [2] c0 45 [2] ee 45 [2] d1 59 }

  condition:
    any of them
}