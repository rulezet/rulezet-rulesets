rule TTP_XOR_WriteProcessMemory_a377 {
  strings:
    $key_a377 = { f4 05 [2] c6 27 [2] c0 12 [2] ee 12 [2] d1 0e }

  condition:
    any of them
}