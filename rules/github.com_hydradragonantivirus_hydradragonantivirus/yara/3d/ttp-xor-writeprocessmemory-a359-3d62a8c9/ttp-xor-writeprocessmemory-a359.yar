rule TTP_XOR_WriteProcessMemory_a359 {
  strings:
    $key_a359 = { f4 2b [2] c6 09 [2] c0 3c [2] ee 3c [2] d1 20 }

  condition:
    any of them
}