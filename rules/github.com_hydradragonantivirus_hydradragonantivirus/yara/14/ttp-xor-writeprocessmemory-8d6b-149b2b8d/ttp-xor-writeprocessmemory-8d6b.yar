rule TTP_XOR_WriteProcessMemory_8d6b {
  strings:
    $key_8d6b = { da 19 [2] e8 3b [2] ee 0e [2] c0 0e [2] ff 12 }

  condition:
    any of them
}