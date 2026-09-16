rule TTP_XOR_WriteProcessMemory_8d12 {
  strings:
    $key_8d12 = { da 60 [2] e8 42 [2] ee 77 [2] c0 77 [2] ff 6b }

  condition:
    any of them
}