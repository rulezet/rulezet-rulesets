rule TTP_XOR_WriteProcessMemory_8d21 {
  strings:
    $key_8d21 = { da 53 [2] e8 71 [2] ee 44 [2] c0 44 [2] ff 58 }

  condition:
    any of them
}