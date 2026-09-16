rule TTP_XOR_WriteProcessMemory_a33b {
  strings:
    $key_a33b = { f4 49 [2] c6 6b [2] c0 5e [2] ee 5e [2] d1 42 }

  condition:
    any of them
}