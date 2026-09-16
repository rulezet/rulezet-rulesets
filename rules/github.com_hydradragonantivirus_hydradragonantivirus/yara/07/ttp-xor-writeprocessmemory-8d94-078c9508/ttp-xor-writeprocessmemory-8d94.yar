rule TTP_XOR_WriteProcessMemory_8d94 {
  strings:
    $key_8d94 = { da e6 [2] e8 c4 [2] ee f1 [2] c0 f1 [2] ff ed }

  condition:
    any of them
}