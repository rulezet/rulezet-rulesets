rule TTP_XOR_WriteProcessMemory_a364 {
  strings:
    $key_a364 = { f4 16 [2] c6 34 [2] c0 01 [2] ee 01 [2] d1 1d }

  condition:
    any of them
}