rule TTP_XOR_WriteProcessMemory_8d73 {
  strings:
    $key_8d73 = { da 01 [2] e8 23 [2] ee 16 [2] c0 16 [2] ff 0a }

  condition:
    any of them
}