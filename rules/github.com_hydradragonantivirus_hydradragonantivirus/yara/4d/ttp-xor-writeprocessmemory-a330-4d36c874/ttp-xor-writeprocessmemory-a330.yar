rule TTP_XOR_WriteProcessMemory_a330 {
  strings:
    $key_a330 = { f4 42 [2] c6 60 [2] c0 55 [2] ee 55 [2] d1 49 }

  condition:
    any of them
}