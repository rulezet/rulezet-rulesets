rule TTP_XOR_WriteProcessMemory_22f6 {
  strings:
    $key_22f6 = { 75 84 [2] 47 a6 [2] 41 93 [2] 6f 93 [2] 50 8f }

  condition:
    any of them
}