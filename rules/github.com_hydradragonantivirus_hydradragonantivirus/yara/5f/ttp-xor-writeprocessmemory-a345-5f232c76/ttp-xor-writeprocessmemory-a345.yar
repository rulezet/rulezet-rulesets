rule TTP_XOR_WriteProcessMemory_a345 {
  strings:
    $key_a345 = { f4 37 [2] c6 15 [2] c0 20 [2] ee 20 [2] d1 3c }

  condition:
    any of them
}