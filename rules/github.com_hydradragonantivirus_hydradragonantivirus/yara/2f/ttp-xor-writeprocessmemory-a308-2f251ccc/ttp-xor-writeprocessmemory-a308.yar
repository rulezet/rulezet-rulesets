rule TTP_XOR_WriteProcessMemory_a308 {
  strings:
    $key_a308 = { f4 7a [2] c6 58 [2] c0 6d [2] ee 6d [2] d1 71 }

  condition:
    any of them
}