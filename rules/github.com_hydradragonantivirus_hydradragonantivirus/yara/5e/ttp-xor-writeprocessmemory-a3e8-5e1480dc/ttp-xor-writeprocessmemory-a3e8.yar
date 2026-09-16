rule TTP_XOR_WriteProcessMemory_a3e8 {
  strings:
    $key_a3e8 = { f4 9a [2] c6 b8 [2] c0 8d [2] ee 8d [2] d1 91 }

  condition:
    any of them
}