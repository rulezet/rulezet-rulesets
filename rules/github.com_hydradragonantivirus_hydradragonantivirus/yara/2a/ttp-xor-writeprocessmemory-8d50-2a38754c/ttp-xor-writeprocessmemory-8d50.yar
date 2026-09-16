rule TTP_XOR_WriteProcessMemory_8d50 {
  strings:
    $key_8d50 = { da 22 [2] e8 00 [2] ee 35 [2] c0 35 [2] ff 29 }

  condition:
    any of them
}