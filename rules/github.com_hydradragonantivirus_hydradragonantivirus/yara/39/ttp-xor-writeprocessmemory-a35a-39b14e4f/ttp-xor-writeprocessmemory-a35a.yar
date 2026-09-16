rule TTP_XOR_WriteProcessMemory_a35a {
  strings:
    $key_a35a = { f4 28 [2] c6 0a [2] c0 3f [2] ee 3f [2] d1 23 }

  condition:
    any of them
}