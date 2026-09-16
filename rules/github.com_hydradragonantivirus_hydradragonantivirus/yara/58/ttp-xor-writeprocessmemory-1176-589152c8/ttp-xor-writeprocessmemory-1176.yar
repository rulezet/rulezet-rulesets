rule TTP_XOR_WriteProcessMemory_1176 {
  strings:
    $key_1176 = { 46 04 [2] 74 26 [2] 72 13 [2] 5c 13 [2] 63 0f }

  condition:
    any of them
}