rule TTP_XOR_WriteProcessMemory_a3ef {
  strings:
    $key_a3ef = { f4 9d [2] c6 bf [2] c0 8a [2] ee 8a [2] d1 96 }

  condition:
    any of them
}