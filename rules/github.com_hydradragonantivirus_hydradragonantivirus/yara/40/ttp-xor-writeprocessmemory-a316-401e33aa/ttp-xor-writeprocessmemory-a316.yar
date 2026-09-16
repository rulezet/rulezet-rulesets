rule TTP_XOR_WriteProcessMemory_a316 {
  strings:
    $key_a316 = { f4 64 [2] c6 46 [2] c0 73 [2] ee 73 [2] d1 6f }

  condition:
    any of them
}