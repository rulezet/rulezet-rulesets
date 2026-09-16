rule TTP_XOR_WriteProcessMemory_a318 {
  strings:
    $key_a318 = { f4 6a [2] c6 48 [2] c0 7d [2] ee 7d [2] d1 61 }

  condition:
    any of them
}