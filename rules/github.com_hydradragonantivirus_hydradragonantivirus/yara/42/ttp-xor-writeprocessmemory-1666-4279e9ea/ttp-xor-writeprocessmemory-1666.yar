rule TTP_XOR_WriteProcessMemory_1666 {
  strings:
    $key_1666 = { 41 14 [2] 73 36 [2] 75 03 [2] 5b 03 [2] 64 1f }

  condition:
    any of them
}