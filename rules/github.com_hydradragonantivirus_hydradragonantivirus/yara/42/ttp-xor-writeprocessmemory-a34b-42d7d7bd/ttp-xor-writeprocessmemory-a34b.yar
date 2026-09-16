rule TTP_XOR_WriteProcessMemory_a34b {
  strings:
    $key_a34b = { f4 39 [2] c6 1b [2] c0 2e [2] ee 2e [2] d1 32 }

  condition:
    any of them
}