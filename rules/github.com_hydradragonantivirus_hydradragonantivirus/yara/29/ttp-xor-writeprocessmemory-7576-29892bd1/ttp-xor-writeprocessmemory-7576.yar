rule TTP_XOR_WriteProcessMemory_7576 {
  strings:
    $key_7576 = { 22 04 [2] 10 26 [2] 16 13 [2] 38 13 [2] 07 0f }

  condition:
    any of them
}