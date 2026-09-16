rule TTP_XOR_WriteProcessMemory_8de3 {
  strings:
    $key_8de3 = { da 91 [2] e8 b3 [2] ee 86 [2] c0 86 [2] ff 9a }

  condition:
    any of them
}