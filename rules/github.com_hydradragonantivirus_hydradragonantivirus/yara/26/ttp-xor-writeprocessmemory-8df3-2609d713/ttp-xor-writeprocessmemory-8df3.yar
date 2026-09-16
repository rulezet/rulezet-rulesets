rule TTP_XOR_WriteProcessMemory_8df3 {
  strings:
    $key_8df3 = { da 81 [2] e8 a3 [2] ee 96 [2] c0 96 [2] ff 8a }

  condition:
    any of them
}