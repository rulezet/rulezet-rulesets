rule TTP_XOR_WriteProcessMemory_2d66 {
  strings:
    $key_2d66 = { 7a 14 [2] 48 36 [2] 4e 03 [2] 60 03 [2] 5f 1f }

  condition:
    any of them
}