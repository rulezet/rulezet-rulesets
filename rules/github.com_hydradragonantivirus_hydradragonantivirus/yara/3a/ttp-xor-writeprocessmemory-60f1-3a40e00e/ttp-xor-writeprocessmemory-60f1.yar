rule TTP_XOR_WriteProcessMemory_60f1 {
  strings:
    $key_60f1 = { 37 83 [2] 05 a1 [2] 03 94 [2] 2d 94 [2] 12 88 }

  condition:
    any of them
}