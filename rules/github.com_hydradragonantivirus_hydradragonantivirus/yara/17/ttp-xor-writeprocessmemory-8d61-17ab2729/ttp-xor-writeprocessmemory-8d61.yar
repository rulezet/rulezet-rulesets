rule TTP_XOR_WriteProcessMemory_8d61 {
  strings:
    $key_8d61 = { da 13 [2] e8 31 [2] ee 04 [2] c0 04 [2] ff 18 }

  condition:
    any of them
}