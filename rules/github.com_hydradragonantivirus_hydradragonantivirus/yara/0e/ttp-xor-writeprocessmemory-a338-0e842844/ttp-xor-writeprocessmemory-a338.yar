rule TTP_XOR_WriteProcessMemory_a338 {
  strings:
    $key_a338 = { f4 4a [2] c6 68 [2] c0 5d [2] ee 5d [2] d1 41 }

  condition:
    any of them
}