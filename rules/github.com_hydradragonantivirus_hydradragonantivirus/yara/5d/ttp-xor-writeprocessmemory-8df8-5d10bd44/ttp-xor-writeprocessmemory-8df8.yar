rule TTP_XOR_WriteProcessMemory_8df8 {
  strings:
    $key_8df8 = { da 8a [2] e8 a8 [2] ee 9d [2] c0 9d [2] ff 81 }

  condition:
    any of them
}