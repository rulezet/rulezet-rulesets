rule TTP_XOR_WriteProcessMemory_a307 {
  strings:
    $key_a307 = { f4 75 [2] c6 57 [2] c0 62 [2] ee 62 [2] d1 7e }

  condition:
    any of them
}