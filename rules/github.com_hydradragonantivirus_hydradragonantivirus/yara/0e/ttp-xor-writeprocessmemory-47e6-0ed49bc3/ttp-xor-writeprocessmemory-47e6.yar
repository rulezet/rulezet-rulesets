rule TTP_XOR_WriteProcessMemory_47e6 {
  strings:
    $key_47e6 = { 10 94 [2] 22 b6 [2] 24 83 [2] 0a 83 [2] 35 9f }

  condition:
    any of them
}