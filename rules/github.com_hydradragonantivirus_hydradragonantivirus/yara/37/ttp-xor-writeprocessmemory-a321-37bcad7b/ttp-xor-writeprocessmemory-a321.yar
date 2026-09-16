rule TTP_XOR_WriteProcessMemory_a321 {
  strings:
    $key_a321 = { f4 53 [2] c6 71 [2] c0 44 [2] ee 44 [2] d1 58 }

  condition:
    any of them
}