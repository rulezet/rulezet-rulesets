rule TTP_XOR_WriteProcessMemory_a30a {
  strings:
    $key_a30a = { f4 78 [2] c6 5a [2] c0 6f [2] ee 6f [2] d1 73 }

  condition:
    any of them
}