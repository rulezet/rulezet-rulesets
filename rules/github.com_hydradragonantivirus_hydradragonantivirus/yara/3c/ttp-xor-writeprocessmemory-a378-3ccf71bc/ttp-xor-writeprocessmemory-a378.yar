rule TTP_XOR_WriteProcessMemory_a378 {
  strings:
    $key_a378 = { f4 0a [2] c6 28 [2] c0 1d [2] ee 1d [2] d1 01 }

  condition:
    any of them
}