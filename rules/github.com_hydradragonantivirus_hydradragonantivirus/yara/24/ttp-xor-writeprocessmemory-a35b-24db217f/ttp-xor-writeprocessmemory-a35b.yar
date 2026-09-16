rule TTP_XOR_WriteProcessMemory_a35b {
  strings:
    $key_a35b = { f4 29 [2] c6 0b [2] c0 3e [2] ee 3e [2] d1 22 }

  condition:
    any of them
}