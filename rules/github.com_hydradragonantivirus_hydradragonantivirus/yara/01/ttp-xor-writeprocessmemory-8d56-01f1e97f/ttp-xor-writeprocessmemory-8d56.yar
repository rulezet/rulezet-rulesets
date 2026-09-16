rule TTP_XOR_WriteProcessMemory_8d56 {
  strings:
    $key_8d56 = { da 24 [2] e8 06 [2] ee 33 [2] c0 33 [2] ff 2f }

  condition:
    any of them
}