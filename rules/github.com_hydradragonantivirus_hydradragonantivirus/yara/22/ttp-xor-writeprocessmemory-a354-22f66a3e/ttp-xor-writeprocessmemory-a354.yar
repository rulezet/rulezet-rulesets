rule TTP_XOR_WriteProcessMemory_a354 {
  strings:
    $key_a354 = { f4 26 [2] c6 04 [2] c0 31 [2] ee 31 [2] d1 2d }

  condition:
    any of them
}