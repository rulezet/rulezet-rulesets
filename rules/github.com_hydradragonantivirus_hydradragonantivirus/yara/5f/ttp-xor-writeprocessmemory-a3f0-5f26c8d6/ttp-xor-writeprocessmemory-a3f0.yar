rule TTP_XOR_WriteProcessMemory_a3f0 {
  strings:
    $key_a3f0 = { f4 82 [2] c6 a0 [2] c0 95 [2] ee 95 [2] d1 89 }

  condition:
    any of them
}