rule TTP_XOR_WriteProcessMemory_8d15 {
  strings:
    $key_8d15 = { da 67 [2] e8 45 [2] ee 70 [2] c0 70 [2] ff 6c }

  condition:
    any of them
}