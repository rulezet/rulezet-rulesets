rule TTP_XOR_WriteProcessMemory_8da2 {
  strings:
    $key_8da2 = { da d0 [2] e8 f2 [2] ee c7 [2] c0 c7 [2] ff db }

  condition:
    any of them
}