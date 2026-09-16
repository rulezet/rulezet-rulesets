rule TTP_XOR_WriteProcessMemory_8d09 {
  strings:
    $key_8d09 = { da 7b [2] e8 59 [2] ee 6c [2] c0 6c [2] ff 70 }

  condition:
    any of them
}