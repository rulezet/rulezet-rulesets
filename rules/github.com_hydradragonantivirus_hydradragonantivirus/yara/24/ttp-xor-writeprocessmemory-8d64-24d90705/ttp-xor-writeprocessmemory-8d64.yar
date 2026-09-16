rule TTP_XOR_WriteProcessMemory_8d64 {
  strings:
    $key_8d64 = { da 16 [2] e8 34 [2] ee 01 [2] c0 01 [2] ff 1d }

  condition:
    any of them
}