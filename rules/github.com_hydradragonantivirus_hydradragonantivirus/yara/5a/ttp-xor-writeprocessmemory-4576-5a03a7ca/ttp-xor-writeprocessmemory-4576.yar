rule TTP_XOR_WriteProcessMemory_4576 {
  strings:
    $key_4576 = { 12 04 [2] 20 26 [2] 26 13 [2] 08 13 [2] 37 0f }

  condition:
    any of them
}