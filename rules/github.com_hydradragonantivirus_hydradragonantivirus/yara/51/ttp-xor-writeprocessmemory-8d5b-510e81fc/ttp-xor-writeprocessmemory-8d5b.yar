rule TTP_XOR_WriteProcessMemory_8d5b {
  strings:
    $key_8d5b = { da 29 [2] e8 0b [2] ee 3e [2] c0 3e [2] ff 22 }

  condition:
    any of them
}