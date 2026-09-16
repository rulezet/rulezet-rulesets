rule TTP_XOR_WriteProcessMemory_a3f3 {
  strings:
    $key_a3f3 = { f4 81 [2] c6 a3 [2] c0 96 [2] ee 96 [2] d1 8a }

  condition:
    any of them
}