rule TTP_XOR_WriteProcessMemory_8d07 {
  strings:
    $key_8d07 = { da 75 [2] e8 57 [2] ee 62 [2] c0 62 [2] ff 7e }

  condition:
    any of them
}