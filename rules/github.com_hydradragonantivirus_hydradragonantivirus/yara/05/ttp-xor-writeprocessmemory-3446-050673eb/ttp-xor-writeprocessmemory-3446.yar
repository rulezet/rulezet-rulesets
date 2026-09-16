rule TTP_XOR_WriteProcessMemory_3446 {
  strings:
    $key_3446 = { 63 34 [2] 51 16 [2] 57 23 [2] 79 23 [2] 46 3f }

  condition:
    any of them
}