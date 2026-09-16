rule TTP_XOR_WriteProcessMemory_8d20 {
  strings:
    $key_8d20 = { da 52 [2] e8 70 [2] ee 45 [2] c0 45 [2] ff 59 }

  condition:
    any of them
}