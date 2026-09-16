rule TTP_XOR_WriteProcessMemory_a36e {
  strings:
    $key_a36e = { f4 1c [2] c6 3e [2] c0 0b [2] ee 0b [2] d1 17 }

  condition:
    any of them
}