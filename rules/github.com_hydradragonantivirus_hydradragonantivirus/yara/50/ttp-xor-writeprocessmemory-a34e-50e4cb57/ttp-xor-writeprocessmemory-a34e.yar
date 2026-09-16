rule TTP_XOR_WriteProcessMemory_a34e {
  strings:
    $key_a34e = { f4 3c [2] c6 1e [2] c0 2b [2] ee 2b [2] d1 37 }

  condition:
    any of them
}