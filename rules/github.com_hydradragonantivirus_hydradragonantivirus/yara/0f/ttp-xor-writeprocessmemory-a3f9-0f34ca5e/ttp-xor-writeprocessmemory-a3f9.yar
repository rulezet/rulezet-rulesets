rule TTP_XOR_WriteProcessMemory_a3f9 {
  strings:
    $key_a3f9 = { f4 8b [2] c6 a9 [2] c0 9c [2] ee 9c [2] d1 80 }

  condition:
    any of them
}