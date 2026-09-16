rule TTP_XOR_WriteProcessMemory_a350 {
  strings:
    $key_a350 = { f4 22 [2] c6 00 [2] c0 35 [2] ee 35 [2] d1 29 }

  condition:
    any of them
}