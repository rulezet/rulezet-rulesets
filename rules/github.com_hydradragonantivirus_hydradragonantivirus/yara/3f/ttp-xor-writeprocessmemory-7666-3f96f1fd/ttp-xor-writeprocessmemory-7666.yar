rule TTP_XOR_WriteProcessMemory_7666 {
  strings:
    $key_7666 = { 21 14 [2] 13 36 [2] 15 03 [2] 3b 03 [2] 04 1f }

  condition:
    any of them
}