rule TTP_XOR_WriteProcessMemory_a322 {
  strings:
    $key_a322 = { f4 50 [2] c6 72 [2] c0 47 [2] ee 47 [2] d1 5b }

  condition:
    any of them
}