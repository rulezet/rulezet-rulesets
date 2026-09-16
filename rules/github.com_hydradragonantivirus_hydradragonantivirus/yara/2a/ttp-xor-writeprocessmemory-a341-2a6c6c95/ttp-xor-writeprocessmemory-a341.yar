rule TTP_XOR_WriteProcessMemory_a341 {
  strings:
    $key_a341 = { f4 33 [2] c6 11 [2] c0 24 [2] ee 24 [2] d1 38 }

  condition:
    any of them
}