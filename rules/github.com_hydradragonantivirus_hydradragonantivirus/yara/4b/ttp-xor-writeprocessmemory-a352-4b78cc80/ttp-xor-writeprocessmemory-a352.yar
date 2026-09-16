rule TTP_XOR_WriteProcessMemory_a352 {
  strings:
    $key_a352 = { f4 20 [2] c6 02 [2] c0 37 [2] ee 37 [2] d1 2b }

  condition:
    any of them
}