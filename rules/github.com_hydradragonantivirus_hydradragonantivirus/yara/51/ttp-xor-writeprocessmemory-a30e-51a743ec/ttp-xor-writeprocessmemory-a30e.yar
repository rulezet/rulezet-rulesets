rule TTP_XOR_WriteProcessMemory_a30e {
  strings:
    $key_a30e = { f4 7c [2] c6 5e [2] c0 6b [2] ee 6b [2] d1 77 }

  condition:
    any of them
}