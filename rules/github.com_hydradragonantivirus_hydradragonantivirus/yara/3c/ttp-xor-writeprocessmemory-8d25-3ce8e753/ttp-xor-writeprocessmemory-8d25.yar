rule TTP_XOR_WriteProcessMemory_8d25 {
  strings:
    $key_8d25 = { da 57 [2] e8 75 [2] ee 40 [2] c0 40 [2] ff 5c }

  condition:
    any of them
}