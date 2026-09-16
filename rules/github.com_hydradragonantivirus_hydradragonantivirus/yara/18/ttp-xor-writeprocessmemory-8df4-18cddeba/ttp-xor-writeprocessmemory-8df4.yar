rule TTP_XOR_WriteProcessMemory_8df4 {
  strings:
    $key_8df4 = { da 86 [2] e8 a4 [2] ee 91 [2] c0 91 [2] ff 8d }

  condition:
    any of them
}