rule TTP_XOR_WriteProcessMemory_8d90 {
  strings:
    $key_8d90 = { da e2 [2] e8 c0 [2] ee f5 [2] c0 f5 [2] ff e9 }

  condition:
    any of them
}