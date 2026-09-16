rule TTP_XOR_WriteProcessMemory_a3ff {
  strings:
    $key_a3ff = { f4 8d [2] c6 af [2] c0 9a [2] ee 9a [2] d1 86 }

  condition:
    any of them
}