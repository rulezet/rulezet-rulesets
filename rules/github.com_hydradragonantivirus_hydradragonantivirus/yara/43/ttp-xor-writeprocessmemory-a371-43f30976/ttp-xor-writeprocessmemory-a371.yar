rule TTP_XOR_WriteProcessMemory_a371 {
  strings:
    $key_a371 = { f4 03 [2] c6 21 [2] c0 14 [2] ee 14 [2] d1 08 }

  condition:
    any of them
}