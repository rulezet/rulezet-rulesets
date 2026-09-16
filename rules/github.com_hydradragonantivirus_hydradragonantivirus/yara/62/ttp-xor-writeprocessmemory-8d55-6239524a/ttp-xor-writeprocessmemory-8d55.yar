rule TTP_XOR_WriteProcessMemory_8d55 {
  strings:
    $key_8d55 = { da 27 [2] e8 05 [2] ee 30 [2] c0 30 [2] ff 2c }

  condition:
    any of them
}