rule TTP_XOR_WriteProcessMemory_a332 {
  strings:
    $key_a332 = { f4 40 [2] c6 62 [2] c0 57 [2] ee 57 [2] d1 4b }

  condition:
    any of them
}