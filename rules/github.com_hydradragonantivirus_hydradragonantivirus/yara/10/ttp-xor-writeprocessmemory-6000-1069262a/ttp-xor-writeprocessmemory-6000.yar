rule TTP_XOR_WriteProcessMemory_6000 {
  strings:
    $key_6000 = { 37 72 [2] 05 50 [2] 03 65 [2] 2d 65 [2] 12 79 }

  condition:
    any of them
}