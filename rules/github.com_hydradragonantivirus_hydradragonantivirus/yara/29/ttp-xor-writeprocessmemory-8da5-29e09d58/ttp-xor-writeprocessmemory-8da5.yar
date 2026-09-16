rule TTP_XOR_WriteProcessMemory_8da5 {
  strings:
    $key_8da5 = { da d7 [2] e8 f5 [2] ee c0 [2] c0 c0 [2] ff dc }

  condition:
    any of them
}