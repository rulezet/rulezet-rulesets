rule TTP_XOR_WriteProcessMemory_a3fe {
  strings:
    $key_a3fe = { f4 8c [2] c6 ae [2] c0 9b [2] ee 9b [2] d1 87 }

  condition:
    any of them
}