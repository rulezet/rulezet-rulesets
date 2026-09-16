rule TTP_XOR_WriteProcessMemory_8d51 {
  strings:
    $key_8d51 = { da 23 [2] e8 01 [2] ee 34 [2] c0 34 [2] ff 28 }

  condition:
    any of them
}