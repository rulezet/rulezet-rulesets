rule TTP_XOR_WriteProcessMemory_a323 {
  strings:
    $key_a323 = { f4 51 [2] c6 73 [2] c0 46 [2] ee 46 [2] d1 5a }

  condition:
    any of them
}