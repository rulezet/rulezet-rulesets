rule TTP_XOR_WriteProcessMemory_a36c {
  strings:
    $key_a36c = { f4 1e [2] c6 3c [2] c0 09 [2] ee 09 [2] d1 15 }

  condition:
    any of them
}