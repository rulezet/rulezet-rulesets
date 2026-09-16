rule TTP_XOR_WriteProcessMemory_8d72 {
  strings:
    $key_8d72 = { da 00 [2] e8 22 [2] ee 17 [2] c0 17 [2] ff 0b }

  condition:
    any of them
}