rule TTP_XOR_WriteProcessMemory_a376 {
  strings:
    $key_a376 = { f4 04 [2] c6 26 [2] c0 13 [2] ee 13 [2] d1 0f }

  condition:
    any of them
}