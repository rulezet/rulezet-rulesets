rule TTP_XOR_WriteProcessMemory_8d02 {
  strings:
    $key_8d02 = { da 70 [2] e8 52 [2] ee 67 [2] c0 67 [2] ff 7b }

  condition:
    any of them
}