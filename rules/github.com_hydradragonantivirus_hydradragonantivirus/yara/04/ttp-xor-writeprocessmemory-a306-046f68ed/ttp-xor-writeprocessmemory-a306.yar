rule TTP_XOR_WriteProcessMemory_a306 {
  strings:
    $key_a306 = { f4 74 [2] c6 56 [2] c0 63 [2] ee 63 [2] d1 7f }

  condition:
    any of them
}