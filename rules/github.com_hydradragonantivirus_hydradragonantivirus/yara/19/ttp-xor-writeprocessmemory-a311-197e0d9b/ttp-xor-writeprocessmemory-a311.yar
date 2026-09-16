rule TTP_XOR_WriteProcessMemory_a311 {
  strings:
    $key_a311 = { f4 63 [2] c6 41 [2] c0 74 [2] ee 74 [2] d1 68 }

  condition:
    any of them
}