rule TTP_XOR_WriteProcessMemory_16d4 {
  strings:
    $key_16d4 = { 41 a6 [2] 73 84 [2] 75 b1 [2] 5b b1 [2] 64 ad }

  condition:
    any of them
}