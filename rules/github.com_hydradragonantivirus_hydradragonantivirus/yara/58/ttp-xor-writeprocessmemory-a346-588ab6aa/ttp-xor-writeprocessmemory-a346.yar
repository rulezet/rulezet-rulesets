rule TTP_XOR_WriteProcessMemory_a346 {
  strings:
    $key_a346 = { f4 34 [2] c6 16 [2] c0 23 [2] ee 23 [2] d1 3f }

  condition:
    any of them
}