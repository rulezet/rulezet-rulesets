rule TTP_XOR_WriteProcessMemory_47f6 {
  strings:
    $key_47f6 = { 10 84 [2] 22 a6 [2] 24 93 [2] 0a 93 [2] 35 8f }

  condition:
    any of them
}