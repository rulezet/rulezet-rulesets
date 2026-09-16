rule TTP_XOR_WriteProcessMemory_8d13 {
  strings:
    $key_8d13 = { da 61 [2] e8 43 [2] ee 76 [2] c0 76 [2] ff 6a }

  condition:
    any of them
}