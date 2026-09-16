rule TTP_XOR_WriteProcessMemory_7166 {
  strings:
    $key_7166 = { 26 14 [2] 14 36 [2] 12 03 [2] 3c 03 [2] 03 1f }

  condition:
    any of them
}