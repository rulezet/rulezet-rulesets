rule TTP_XOR_WriteProcessMemory_a328 {
  strings:
    $key_a328 = { f4 5a [2] c6 78 [2] c0 4d [2] ee 4d [2] d1 51 }

  condition:
    any of them
}