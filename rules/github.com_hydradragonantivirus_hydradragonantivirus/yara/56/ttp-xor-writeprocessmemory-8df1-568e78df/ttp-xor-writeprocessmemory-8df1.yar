rule TTP_XOR_WriteProcessMemory_8df1 {
  strings:
    $key_8df1 = { da 83 [2] e8 a1 [2] ee 94 [2] c0 94 [2] ff 88 }

  condition:
    any of them
}