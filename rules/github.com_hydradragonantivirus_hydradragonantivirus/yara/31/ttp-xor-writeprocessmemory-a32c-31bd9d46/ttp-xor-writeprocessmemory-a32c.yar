rule TTP_XOR_WriteProcessMemory_a32c {
  strings:
    $key_a32c = { f4 5e [2] c6 7c [2] c0 49 [2] ee 49 [2] d1 55 }

  condition:
    any of them
}