rule TTP_XOR_WriteProcessMemory_a358 {
  strings:
    $key_a358 = { f4 2a [2] c6 08 [2] c0 3d [2] ee 3d [2] d1 21 }

  condition:
    any of them
}