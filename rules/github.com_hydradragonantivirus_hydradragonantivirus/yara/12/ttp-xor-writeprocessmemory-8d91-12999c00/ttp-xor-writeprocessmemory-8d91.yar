rule TTP_XOR_WriteProcessMemory_8d91 {
  strings:
    $key_8d91 = { da e3 [2] e8 c1 [2] ee f4 [2] c0 f4 [2] ff e8 }

  condition:
    any of them
}