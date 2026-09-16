rule TTP_XOR_WriteProcessMemory_8d63 {
  strings:
    $key_8d63 = { da 11 [2] e8 33 [2] ee 06 [2] c0 06 [2] ff 1a }

  condition:
    any of them
}