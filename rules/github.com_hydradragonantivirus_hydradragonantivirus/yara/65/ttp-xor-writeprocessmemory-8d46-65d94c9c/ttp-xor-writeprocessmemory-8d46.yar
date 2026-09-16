rule TTP_XOR_WriteProcessMemory_8d46 {
  strings:
    $key_8d46 = { da 34 [2] e8 16 [2] ee 23 [2] c0 23 [2] ff 3f }

  condition:
    any of them
}