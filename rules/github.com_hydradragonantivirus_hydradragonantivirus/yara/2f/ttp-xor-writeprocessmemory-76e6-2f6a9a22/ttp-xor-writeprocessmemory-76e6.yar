rule TTP_XOR_WriteProcessMemory_76e6 {
  strings:
    $key_76e6 = { 21 94 [2] 13 b6 [2] 15 83 [2] 3b 83 [2] 04 9f }

  condition:
    any of them
}