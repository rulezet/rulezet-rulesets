rule TTP_XOR_WriteProcessMemory_8d04 {
  strings:
    $key_8d04 = { da 76 [2] e8 54 [2] ee 61 [2] c0 61 [2] ff 7d }

  condition:
    any of them
}