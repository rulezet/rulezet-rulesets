rule TTP_XOR_WriteProcessMemory_8da7 {
  strings:
    $key_8da7 = { da d5 [2] e8 f7 [2] ee c2 [2] c0 c2 [2] ff de }

  condition:
    any of them
}