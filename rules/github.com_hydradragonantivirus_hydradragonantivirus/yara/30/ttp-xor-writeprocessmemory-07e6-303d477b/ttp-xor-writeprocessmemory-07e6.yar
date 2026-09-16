rule TTP_XOR_WriteProcessMemory_07e6 {
  strings:
    $key_07e6 = { 50 94 [2] 62 b6 [2] 64 83 [2] 4a 83 [2] 75 9f }

  condition:
    any of them
}