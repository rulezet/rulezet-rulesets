rule TTP_XOR_WriteProcessMemory_a379 {
  strings:
    $key_a379 = { f4 0b [2] c6 29 [2] c0 1c [2] ee 1c [2] d1 00 }

  condition:
    any of them
}