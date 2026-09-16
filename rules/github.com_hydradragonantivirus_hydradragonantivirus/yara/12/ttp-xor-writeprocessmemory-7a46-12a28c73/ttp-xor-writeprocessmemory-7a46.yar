rule TTP_XOR_WriteProcessMemory_7a46 {
  strings:
    $key_7a46 = { 2d 34 [2] 1f 16 [2] 19 23 [2] 37 23 [2] 08 3f }

  condition:
    any of them
}