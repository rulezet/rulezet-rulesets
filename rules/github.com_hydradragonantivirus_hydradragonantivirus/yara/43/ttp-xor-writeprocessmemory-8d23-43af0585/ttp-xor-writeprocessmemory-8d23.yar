rule TTP_XOR_WriteProcessMemory_8d23 {
  strings:
    $key_8d23 = { da 51 [2] e8 73 [2] ee 46 [2] c0 46 [2] ff 5a }

  condition:
    any of them
}