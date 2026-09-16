rule TTP_XOR_WriteProcessMemory_a349 {
  strings:
    $key_a349 = { f4 3b [2] c6 19 [2] c0 2c [2] ee 2c [2] d1 30 }

  condition:
    any of them
}