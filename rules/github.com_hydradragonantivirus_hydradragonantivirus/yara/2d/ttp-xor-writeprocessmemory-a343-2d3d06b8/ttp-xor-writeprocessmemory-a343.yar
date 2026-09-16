rule TTP_XOR_WriteProcessMemory_a343 {
  strings:
    $key_a343 = { f4 31 [2] c6 13 [2] c0 26 [2] ee 26 [2] d1 3a }

  condition:
    any of them
}