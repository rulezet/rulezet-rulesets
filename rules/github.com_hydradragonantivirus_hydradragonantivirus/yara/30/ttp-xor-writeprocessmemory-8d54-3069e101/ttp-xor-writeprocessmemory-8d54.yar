rule TTP_XOR_WriteProcessMemory_8d54 {
  strings:
    $key_8d54 = { da 26 [2] e8 04 [2] ee 31 [2] c0 31 [2] ff 2d }

  condition:
    any of them
}