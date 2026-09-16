rule TTP_XOR_WriteProcessMemory_8d74 {
  strings:
    $key_8d74 = { da 06 [2] e8 24 [2] ee 11 [2] c0 11 [2] ff 0d }

  condition:
    any of them
}