rule TTP_XOR_WriteProcessMemory_a30d {
  strings:
    $key_a30d = { f4 7f [2] c6 5d [2] c0 68 [2] ee 68 [2] d1 74 }

  condition:
    any of them
}