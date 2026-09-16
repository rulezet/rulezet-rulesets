rule TTP_XOR_WriteProcessMemory_8d42 {
  strings:
    $key_8d42 = { da 30 [2] e8 12 [2] ee 27 [2] c0 27 [2] ff 3b }

  condition:
    any of them
}