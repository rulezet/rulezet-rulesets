rule TTP_XOR_WriteProcessMemory_8d7c {
  strings:
    $key_8d7c = { da 0e [2] e8 2c [2] ee 19 [2] c0 19 [2] ff 05 }

  condition:
    any of them
}