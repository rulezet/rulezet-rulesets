rule TTP_XOR_WriteProcessMemory_8df6 {
  strings:
    $key_8df6 = { da 84 [2] e8 a6 [2] ee 93 [2] c0 93 [2] ff 8f }

  condition:
    any of them
}