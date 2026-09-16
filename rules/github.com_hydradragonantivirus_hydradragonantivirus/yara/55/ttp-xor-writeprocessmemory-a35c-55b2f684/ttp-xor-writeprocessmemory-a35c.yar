rule TTP_XOR_WriteProcessMemory_a35c {
  strings:
    $key_a35c = { f4 2e [2] c6 0c [2] c0 39 [2] ee 39 [2] d1 25 }

  condition:
    any of them
}