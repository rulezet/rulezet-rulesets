rule TTP_XOR_WriteProcessMemory_77e6 {
  strings:
    $key_77e6 = { 20 94 [2] 12 b6 [2] 14 83 [2] 3a 83 [2] 05 9f }

  condition:
    any of them
}