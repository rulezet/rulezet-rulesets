rule TTP_XOR_WriteProcessMemory_3566 {
  strings:
    $key_3566 = { 62 14 [2] 50 36 [2] 56 03 [2] 78 03 [2] 47 1f }

  condition:
    any of them
}