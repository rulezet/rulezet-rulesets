rule TTP_XOR_WriteProcessMemory_a372 {
  strings:
    $key_a372 = { f4 00 [2] c6 22 [2] c0 17 [2] ee 17 [2] d1 0b }

  condition:
    any of them
}