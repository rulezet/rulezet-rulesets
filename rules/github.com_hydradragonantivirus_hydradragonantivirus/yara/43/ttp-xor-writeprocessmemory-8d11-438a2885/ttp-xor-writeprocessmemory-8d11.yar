rule TTP_XOR_WriteProcessMemory_8d11 {
  strings:
    $key_8d11 = { da 63 [2] e8 41 [2] ee 74 [2] c0 74 [2] ff 68 }

  condition:
    any of them
}