rule TTP_XOR_WriteProcessMemory_a369 {
  strings:
    $key_a369 = { f4 1b [2] c6 39 [2] c0 0c [2] ee 0c [2] d1 10 }

  condition:
    any of them
}