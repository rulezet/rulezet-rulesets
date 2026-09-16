rule TTP_XOR_WriteProcessMemory_8d66 {
  strings:
    $key_8d66 = { da 14 [2] e8 36 [2] ee 03 [2] c0 03 [2] ff 1f }

  condition:
    any of them
}