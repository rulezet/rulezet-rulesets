rule TTP_XOR_WriteProcessMemory_5346 {
  strings:
    $key_5346 = { 04 34 [2] 36 16 [2] 30 23 [2] 1e 23 [2] 21 3f }

  condition:
    any of them
}