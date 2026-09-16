rule TTP_XOR_WriteProcessMemory_8d22 {
  strings:
    $key_8d22 = { da 50 [2] e8 72 [2] ee 47 [2] c0 47 [2] ff 5b }

  condition:
    any of them
}