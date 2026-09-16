rule TTP_XOR_WriteProcessMemory_a375 {
  strings:
    $key_a375 = { f4 07 [2] c6 25 [2] c0 10 [2] ee 10 [2] d1 0c }

  condition:
    any of them
}