rule TTP_XOR_WriteProcessMemory_a325 {
  strings:
    $key_a325 = { f4 57 [2] c6 75 [2] c0 40 [2] ee 40 [2] d1 5c }

  condition:
    any of them
}