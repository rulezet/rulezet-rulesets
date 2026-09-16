rule TTP_XOR_WriteProcessMemory_53f6 {
  strings:
    $key_53f6 = { 04 84 [2] 36 a6 [2] 30 93 [2] 1e 93 [2] 21 8f }

  condition:
    any of them
}