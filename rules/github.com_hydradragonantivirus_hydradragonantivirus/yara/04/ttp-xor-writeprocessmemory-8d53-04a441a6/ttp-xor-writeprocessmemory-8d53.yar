rule TTP_XOR_WriteProcessMemory_8d53 {
  strings:
    $key_8d53 = { da 21 [2] e8 03 [2] ee 36 [2] c0 36 [2] ff 2a }

  condition:
    any of them
}