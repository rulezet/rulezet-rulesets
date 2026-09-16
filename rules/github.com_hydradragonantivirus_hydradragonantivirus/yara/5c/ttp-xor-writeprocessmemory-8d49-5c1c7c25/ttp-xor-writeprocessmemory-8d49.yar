rule TTP_XOR_WriteProcessMemory_8d49 {
  strings:
    $key_8d49 = { da 3b [2] e8 19 [2] ee 2c [2] c0 2c [2] ff 30 }

  condition:
    any of them
}