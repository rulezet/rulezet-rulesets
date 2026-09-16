rule TTP_XOR_WriteProcessMemory_a3f8 {
  strings:
    $key_a3f8 = { f4 8a [2] c6 a8 [2] c0 9d [2] ee 9d [2] d1 81 }

  condition:
    any of them
}