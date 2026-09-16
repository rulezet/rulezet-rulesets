rule TTP_XOR_WriteProcessMemory_42d4 {
  strings:
    $key_42d4 = { 15 a6 [2] 27 84 [2] 21 b1 [2] 0f b1 [2] 30 ad }

  condition:
    any of them
}