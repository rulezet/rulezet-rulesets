rule TTP_XOR_WriteProcessMemory_a37f {
  strings:
    $key_a37f = { f4 0d [2] c6 2f [2] c0 1a [2] ee 1a [2] d1 06 }

  condition:
    any of them
}