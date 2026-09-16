rule TTP_XOR_WriteProcessMemory_4846 {
  strings:
    $key_4846 = { 1f 34 [2] 2d 16 [2] 2b 23 [2] 05 23 [2] 3a 3f }

  condition:
    any of them
}