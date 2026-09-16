rule TTP_XOR_WriteProcessMemory_8d68 {
  strings:
    $key_8d68 = { da 1a [2] e8 38 [2] ee 0d [2] c0 0d [2] ff 11 }

  condition:
    any of them
}