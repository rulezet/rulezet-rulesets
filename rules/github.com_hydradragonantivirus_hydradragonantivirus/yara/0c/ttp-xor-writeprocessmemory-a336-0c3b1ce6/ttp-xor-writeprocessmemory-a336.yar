rule TTP_XOR_WriteProcessMemory_a336 {
  strings:
    $key_a336 = { f4 44 [2] c6 66 [2] c0 53 [2] ee 53 [2] d1 4f }

  condition:
    any of them
}