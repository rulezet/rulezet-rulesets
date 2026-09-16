rule TTP_XOR_WriteProcessMemory_8de7 {
  strings:
    $key_8de7 = { da 95 [2] e8 b7 [2] ee 82 [2] c0 82 [2] ff 9e }

  condition:
    any of them
}