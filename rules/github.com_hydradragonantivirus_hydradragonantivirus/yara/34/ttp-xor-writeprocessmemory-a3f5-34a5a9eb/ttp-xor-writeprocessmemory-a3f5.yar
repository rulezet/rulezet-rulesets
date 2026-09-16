rule TTP_XOR_WriteProcessMemory_a3f5 {
  strings:
    $key_a3f5 = { f4 87 [2] c6 a5 [2] c0 90 [2] ee 90 [2] d1 8c }

  condition:
    any of them
}