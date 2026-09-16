rule TTP_XOR_WriteProcessMemory_a3f6 {
  strings:
    $key_a3f6 = { f4 84 [2] c6 a6 [2] c0 93 [2] ee 93 [2] d1 8f }

  condition:
    any of them
}