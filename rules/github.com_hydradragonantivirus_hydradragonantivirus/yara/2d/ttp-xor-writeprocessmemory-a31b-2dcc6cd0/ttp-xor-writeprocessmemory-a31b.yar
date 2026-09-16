rule TTP_XOR_WriteProcessMemory_a31b {
  strings:
    $key_a31b = { f4 69 [2] c6 4b [2] c0 7e [2] ee 7e [2] d1 62 }

  condition:
    any of them
}