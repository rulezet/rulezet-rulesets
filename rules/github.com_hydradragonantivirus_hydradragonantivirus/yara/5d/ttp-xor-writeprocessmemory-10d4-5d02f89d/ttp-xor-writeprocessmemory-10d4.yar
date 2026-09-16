rule TTP_XOR_WriteProcessMemory_10d4 {
  strings:
    $key_10d4 = { 47 a6 [2] 75 84 [2] 73 b1 [2] 5d b1 [2] 62 ad }

  condition:
    any of them
}