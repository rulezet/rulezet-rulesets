rule TTP_XOR_WriteProcessMemory_8d69 {
  strings:
    $key_8d69 = { da 1b [2] e8 39 [2] ee 0c [2] c0 0c [2] ff 10 }

  condition:
    any of them
}