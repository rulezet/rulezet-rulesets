rule TTP_XOR_WriteProcessMemory_8de4 {
  strings:
    $key_8de4 = { da 96 [2] e8 b4 [2] ee 81 [2] c0 81 [2] ff 9d }

  condition:
    any of them
}