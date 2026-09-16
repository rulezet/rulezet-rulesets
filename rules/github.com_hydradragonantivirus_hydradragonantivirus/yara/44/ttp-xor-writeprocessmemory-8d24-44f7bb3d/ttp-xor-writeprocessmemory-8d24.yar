rule TTP_XOR_WriteProcessMemory_8d24 {
  strings:
    $key_8d24 = { da 56 [2] e8 74 [2] ee 41 [2] c0 41 [2] ff 5d }

  condition:
    any of them
}