rule TTP_XOR_WriteProcessMemory_a304 {
  strings:
    $key_a304 = { f4 76 [2] c6 54 [2] c0 61 [2] ee 61 [2] d1 7d }

  condition:
    any of them
}