rule TTP_XOR_WriteProcessMemory_a35e {
  strings:
    $key_a35e = { f4 2c [2] c6 0e [2] c0 3b [2] ee 3b [2] d1 27 }

  condition:
    any of them
}