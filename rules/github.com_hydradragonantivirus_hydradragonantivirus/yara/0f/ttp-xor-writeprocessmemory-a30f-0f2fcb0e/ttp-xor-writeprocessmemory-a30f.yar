rule TTP_XOR_WriteProcessMemory_a30f {
  strings:
    $key_a30f = { f4 7d [2] c6 5f [2] c0 6a [2] ee 6a [2] d1 76 }

  condition:
    any of them
}