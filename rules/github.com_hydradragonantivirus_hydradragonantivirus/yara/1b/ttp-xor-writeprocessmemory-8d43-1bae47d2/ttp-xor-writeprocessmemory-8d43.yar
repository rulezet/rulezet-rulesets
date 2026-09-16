rule TTP_XOR_WriteProcessMemory_8d43 {
  strings:
    $key_8d43 = { da 31 [2] e8 13 [2] ee 26 [2] c0 26 [2] ff 3a }

  condition:
    any of them
}