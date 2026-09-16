rule TTP_XOR_WriteProcessMemory_10f6 {
  strings:
    $key_10f6 = { 47 84 [2] 75 a6 [2] 73 93 [2] 5d 93 [2] 62 8f }

  condition:
    any of them
}