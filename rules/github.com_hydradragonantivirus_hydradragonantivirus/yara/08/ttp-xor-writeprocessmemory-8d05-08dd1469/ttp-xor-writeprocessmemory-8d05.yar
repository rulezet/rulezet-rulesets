rule TTP_XOR_WriteProcessMemory_8d05 {
  strings:
    $key_8d05 = { da 77 [2] e8 55 [2] ee 60 [2] c0 60 [2] ff 7c }

  condition:
    any of them
}