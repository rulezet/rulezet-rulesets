rule TTP_XOR_WriteProcessMemory_a34c {
  strings:
    $key_a34c = { f4 3e [2] c6 1c [2] c0 29 [2] ee 29 [2] d1 35 }

  condition:
    any of them
}