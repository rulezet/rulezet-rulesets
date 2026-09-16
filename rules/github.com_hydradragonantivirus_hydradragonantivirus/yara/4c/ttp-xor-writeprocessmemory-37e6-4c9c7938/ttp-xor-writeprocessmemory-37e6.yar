rule TTP_XOR_WriteProcessMemory_37e6 {
  strings:
    $key_37e6 = { 60 94 [2] 52 b6 [2] 54 83 [2] 7a 83 [2] 45 9f }

  condition:
    any of them
}