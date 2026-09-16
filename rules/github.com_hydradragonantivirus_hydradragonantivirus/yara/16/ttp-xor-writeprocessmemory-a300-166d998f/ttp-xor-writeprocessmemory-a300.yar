rule TTP_XOR_WriteProcessMemory_a300 {
  strings:
    $key_a300 = { f4 72 [2] c6 50 [2] c0 65 [2] ee 65 [2] d1 79 }

  condition:
    any of them
}