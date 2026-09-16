rule TTP_XOR_WriteProcessMemory_a37e {
  strings:
    $key_a37e = { f4 0c [2] c6 2e [2] c0 1b [2] ee 1b [2] d1 07 }

  condition:
    any of them
}