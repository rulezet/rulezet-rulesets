rule TTP_XOR_WriteProcessMemory_a303 {
  strings:
    $key_a303 = { f4 71 [2] c6 53 [2] c0 66 [2] ee 66 [2] d1 7a }

  condition:
    any of them
}