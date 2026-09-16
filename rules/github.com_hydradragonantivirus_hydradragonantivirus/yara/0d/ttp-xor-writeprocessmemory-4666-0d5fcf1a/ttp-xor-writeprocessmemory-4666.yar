rule TTP_XOR_WriteProcessMemory_4666 {
  strings:
    $key_4666 = { 11 14 [2] 23 36 [2] 25 03 [2] 0b 03 [2] 34 1f }

  condition:
    any of them
}